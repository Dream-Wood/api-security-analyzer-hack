package active.discovery;

import active.http.HttpClient;
import active.model.TestRequest;
import active.model.TestResponse;

import java.util.*;
import java.util.logging.Logger;

/**
 * Анализатор HTTP ответов для определения существования незадокументированного эндпоинта.
 * Использует умную эвристику, чтобы отличить реальный эндпоинт от 404.
 *
 * <p>Критерии определения существования:
 * <ul>
 *   <li>Статус код (200-299, 401, 403, 405, 500+)</li>
 *   <li>Размер ответа (отличается от baseline 404)</li>
 *   <li>Специфичные заголовки (X-API-Version, Content-Type и др.)</li>
 *   <li>Время ответа (значительно отличается от baseline)</li>
 *   <li>Содержимое ответа (шаблоны API responses)</li>
 * </ul>
 */
public final class ResponseAnalyzer {
    private static final Logger logger = Logger.getLogger(ResponseAnalyzer.class.getName());

    // Baseline для сравнения (типичный 404 ответ)
    private BaselineResponse baseline;

    // Пороги для определения
    private static final double RESPONSE_SIZE_DIFF_THRESHOLD = 0.3; // 30% difference
    private static final long RESPONSE_TIME_DIFF_THRESHOLD_MS = 100; // 100ms difference

    // Статус коды указывающие на существование эндпоинта
    private static final Set<Integer> EXISTENCE_STATUS_CODES = Set.of(
        200, 201, 202, 204, // Success
        301, 302, 303, 307, 308, // Redirects
        400, 401, 403, 405, 422, // Client errors (but endpoint exists!)
        500, 501, 502, 503 // Server errors (endpoint exists, but broken)
    );

    // Заголовки указывающие на API endpoint
    private static final Set<String> API_HEADERS = Set.of(
        "x-api-version",
        "x-api-key",
        "x-ratelimit-limit",
        "x-request-id",
        "x-correlation-id",
        "api-version"
    );

    // Паттерны в теле ответа указывающие на API
    private static final List<String> API_BODY_PATTERNS = List.of(
        "\"error\":", "\"message\":", "\"data\":",
        "\"success\":", "\"status\":",
        "<?xml", "{\"", "[{"
    );

    public ResponseAnalyzer() {
        this.baseline = null;
    }

    /**
     * Устанавливает baseline - типичный 404 ответ для сравнения.
     * Должен быть вызван перед началом discovery.
     *
     * @param baseUrl базовый URL API
     * @param httpClient HTTP клиент
     */
    public void establishBaseline(String baseUrl, HttpClient httpClient) {
        logger.info("Establishing baseline 404 response...");

        try {
            // Пробуем несколько заведомо несуществующих путей
            List<String> testPaths = List.of(
                "/this-path-definitely-does-not-exist-" + UUID.randomUUID(),
                "/nonexistent-endpoint-" + System.currentTimeMillis(),
                "/random-" + UUID.randomUUID().toString().substring(0, 8)
            );

            List<BaselineResponse> samples = new ArrayList<>();

            for (String testPath : testPaths) {
                try {
                    long startTime = System.currentTimeMillis();
                    TestRequest request = TestRequest.builder()
                        .url(baseUrl + testPath)
                        .method("GET")
                        .build();
                    TestResponse response = httpClient.execute(request);
                    long responseTime = System.currentTimeMillis() - startTime;

                    samples.add(new BaselineResponse(
                        response.getStatusCode(),
                        response.getBody() != null ? response.getBody().length() : 0,
                        responseTime,
                        convertHeaders(response.getHeaders())
                    ));
                } catch (Exception e) {
                    logger.fine("Failed to get baseline sample: " + e.getMessage());
                }
            }

            if (!samples.isEmpty()) {
                // Use median values from samples
                baseline = calculateMedianBaseline(samples);
                logger.info("Baseline established: status=" + baseline.statusCode +
                           ", size=" + baseline.contentLength +
                           ", time=" + baseline.responseTimeMs + "ms");
            } else {
                logger.warning("Failed to establish baseline, using defaults");
                baseline = new BaselineResponse(404, 0, 100, Map.of());
            }
        } catch (Exception e) {
            logger.warning("Error establishing baseline: " + e.getMessage());
            baseline = new BaselineResponse(404, 0, 100, Map.of());
        }
    }

    /**
     * Вычисляет медианный baseline из нескольких образцов.
     */
    private BaselineResponse calculateMedianBaseline(List<BaselineResponse> samples) {
        if (samples.isEmpty()) {
            return new BaselineResponse(404, 0, 100, Map.of());
        }

        // Sort by content length to find median
        samples.sort(Comparator.comparingInt(r -> r.contentLength));
        BaselineResponse median = samples.get(samples.size() / 2);

        // Use most common status code
        int statusCode = samples.stream()
            .mapToInt(r -> r.statusCode)
            .max()
            .orElse(404);

        return new BaselineResponse(
            statusCode,
            median.contentLength,
            median.responseTimeMs,
            median.headers
        );
    }

    /**
     * Анализирует ответ и определяет, существует ли эндпоинт.
     *
     * @param response HTTP ответ
     * @param responseTimeMs время ответа в миллисекундах
     * @return результат анализа
     */
    public AnalysisResult analyze(TestResponse response, long responseTimeMs) {
        if (baseline == null) {
            logger.warning("Baseline not established, analysis may be inaccurate");
        }

        int statusCode = response.getStatusCode();
        String body = response.getBody() != null ? response.getBody() : "";
        Map<String, String> headers = convertHeaders(response.getHeaders());

        // Check status code
        EndpointExistence existence = determineExistence(statusCode, body, headers, responseTimeMs);
        double confidence = calculateConfidence(statusCode, body, headers, responseTimeMs);
        String reason = buildReason(existence, statusCode, body, headers, responseTimeMs);

        return new AnalysisResult(existence, confidence, reason, statusCode);
    }

    /**
     * Определяет существование эндпоинта на основе различных факторов.
     */
    private EndpointExistence determineExistence(int statusCode, String body,
                                                   Map<String, String> headers, long responseTimeMs) {
        // 1. Check status code
        if (EXISTENCE_STATUS_CODES.contains(statusCode)) {
            // 401/403 - almost certainly exists, requires auth
            if (statusCode == 401 || statusCode == 403) {
                return EndpointExistence.EXISTS;
            }
            // 405 - exists, but wrong method
            if (statusCode == 405) {
                return EndpointExistence.EXISTS;
            }
            // 2xx - definitely exists
            if (statusCode >= 200 && statusCode < 300) {
                return EndpointExistence.EXISTS;
            }
            // 5xx - likely exists but has errors
            if (statusCode >= 500) {
                return EndpointExistence.LIKELY_EXISTS;
            }
        }

        // 2. Special handling for 404 - be very conservative!
        // Most servers return 404 with JSON error messages, don't count this as "exists"
        if (statusCode == 404) {
            if (baseline != null && statusCode == baseline.statusCode) {
                boolean sizeDifferent = isSizeDifferent(body.length(), baseline.contentLength);
                boolean timeDifferent = isTimeDifferent(responseTimeMs, baseline.responseTimeMs);
                boolean hasApiHeaders = hasApiHeaders(headers);
                boolean hasApiBody = hasApiBodyPattern(body);

                // For 404, require STRONG evidence (3-4 signals, not just 2)
                int signals = 0;
                if (sizeDifferent) signals++;
                if (timeDifferent) signals++;
                if (hasApiHeaders) signals++;
                // Don't count API body pattern as strong signal for 404 - most servers return JSON errors!
                // if (hasApiBody) signals++;

                // Require at least 3 strong signals to consider 404 as "possibly exists"
                if (signals >= 3) {
                    return EndpointExistence.POSSIBLY_EXISTS;
                }
            }
            // Default: 404 = does not exist
            return EndpointExistence.DOES_NOT_EXIST;
        }

        // 3. For other status codes matching baseline
        if (baseline != null && statusCode == baseline.statusCode) {
            boolean sizeDifferent = isSizeDifferent(body.length(), baseline.contentLength);
            boolean timeDifferent = isTimeDifferent(responseTimeMs, baseline.responseTimeMs);
            boolean hasApiHeaders = hasApiHeaders(headers);
            boolean hasApiBody = hasApiBodyPattern(body);

            int signals = 0;
            if (sizeDifferent) signals++;
            if (timeDifferent) signals++;
            if (hasApiHeaders) signals++;
            if (hasApiBody) signals++;

            if (signals >= 2) {
                return EndpointExistence.LIKELY_EXISTS;
            } else if (signals == 1) {
                return EndpointExistence.POSSIBLY_EXISTS;
            }
        }

        // 4. Check for API-specific headers even on other status codes
        if (hasApiHeaders(headers) && hasApiBodyPattern(body)) {
            return EndpointExistence.POSSIBLY_EXISTS;
        }

        return EndpointExistence.DOES_NOT_EXIST;
    }

    /**
     * Проверяет, значительно ли отличается размер ответа от baseline.
     */
    private boolean isSizeDifferent(int actualSize, int baselineSize) {
        if (baselineSize == 0) {
            return actualSize > 0;
        }
        double diff = Math.abs((double) (actualSize - baselineSize) / baselineSize);
        return diff > RESPONSE_SIZE_DIFF_THRESHOLD;
    }

    /**
     * Проверяет, значительно ли отличается время ответа от baseline.
     */
    private boolean isTimeDifferent(long actualTime, long baselineTime) {
        return Math.abs(actualTime - baselineTime) > RESPONSE_TIME_DIFF_THRESHOLD_MS;
    }

    /**
     * Проверяет наличие API-специфичных заголовков.
     */
    private boolean hasApiHeaders(Map<String, String> headers) {
        return headers.keySet().stream()
            .anyMatch(header -> API_HEADERS.contains(header.toLowerCase()));
    }

    /**
     * Проверяет наличие API-специфичных паттернов в теле ответа.
     */
    private boolean hasApiBodyPattern(String body) {
        if (body == null || body.isEmpty()) {
            return false;
        }
        return API_BODY_PATTERNS.stream()
            .anyMatch(body::contains);
    }

    /**
     * Вычисляет уровень уверенности в определении (0.0 - 1.0).
     */
    private double calculateConfidence(int statusCode, String body,
                                        Map<String, String> headers, long responseTimeMs) {
        double confidence = 0.0;

        // High confidence for certain status codes
        if (statusCode == 401 || statusCode == 403 || statusCode == 405) {
            confidence = 0.95;
        } else if (statusCode >= 200 && statusCode < 300) {
            confidence = 1.0;
        } else if (statusCode >= 500) {
            confidence = 0.7;
        } else if (statusCode == 404) {
            // For 404, be very conservative - most are genuine "not found"
            // Start with very low confidence
            confidence = 0.05;

            if (baseline != null) {
                // Only increase confidence for significant differences
                if (isSizeDifferent(body.length(), baseline.contentLength)) {
                    confidence += 0.15; // Reduced from 0.2
                }
                if (isTimeDifferent(responseTimeMs, baseline.responseTimeMs)) {
                    confidence += 0.1;
                }
            }
            if (hasApiHeaders(headers)) {
                confidence += 0.2; // Reduced from 0.3
            }
            // DON'T increase confidence for API body pattern - most 404s have JSON!
            // if (hasApiBodyPattern(body)) {
            //     confidence += 0.2;
            // }

            // Maximum confidence for 404 should be low (0.5) to avoid false positives
            confidence = Math.min(0.5, confidence);
        }

        return Math.min(1.0, confidence);
    }

    /**
     * Строит человекочитаемое объяснение результата.
     */
    private String buildReason(EndpointExistence existence, int statusCode,
                                String body, Map<String, String> headers, long responseTimeMs) {
        StringBuilder reason = new StringBuilder();

        if (statusCode == 401) {
            reason.append("Requires authentication (401)");
        } else if (statusCode == 403) {
            reason.append("Forbidden - endpoint exists but access denied (403)");
        } else if (statusCode == 405) {
            reason.append("Method not allowed - endpoint exists (405)");
        } else if (statusCode >= 200 && statusCode < 300) {
            reason.append("Success response (").append(statusCode).append(")");
        } else if (statusCode >= 500) {
            reason.append("Server error - endpoint likely exists (").append(statusCode).append(")");
        } else if (existence != EndpointExistence.DOES_NOT_EXIST) {
            reason.append("Response differs from baseline 404");
            if (hasApiHeaders(headers)) {
                reason.append(", has API headers");
            }
            if (hasApiBodyPattern(body)) {
                reason.append(", has API response pattern");
            }
        } else {
            reason.append("Standard 404 response");
        }

        return reason.toString();
    }

    /**
     * Преобразует Map<String, List<String>> в Map<String, String>, беря первое значение из списка.
     */
    private Map<String, String> convertHeaders(Map<String, List<String>> headers) {
        if (headers == null || headers.isEmpty()) {
            return Map.of();
        }
        Map<String, String> result = new HashMap<>();
        headers.forEach((key, values) -> {
            if (values != null && !values.isEmpty()) {
                result.put(key, values.get(0));
            }
        });
        return result;
    }

    /**
     * Baseline ответ для сравнения.
     */
    private record BaselineResponse(
        int statusCode,
        int contentLength,
        long responseTimeMs,
        Map<String, String> headers
    ) {}

    /**
     * Результат анализа ответа.
     */
    public record AnalysisResult(
        EndpointExistence existence,
        double confidence,
        String reason,
        int statusCode
    ) {
        public boolean endpointExists() {
            return existence == EndpointExistence.EXISTS ||
                   existence == EndpointExistence.LIKELY_EXISTS;
        }

        public boolean endpointPossiblyExists() {
            return existence == EndpointExistence.POSSIBLY_EXISTS;
        }
    }

    /**
     * Уровень уверенности в существовании эндпоинта.
     */
    public enum EndpointExistence {
        /** Эндпоинт точно существует */
        EXISTS,

        /** Эндпоинт скорее всего существует */
        LIKELY_EXISTS,

        /** Эндпоинт возможно существует */
        POSSIBLY_EXISTS,

        /** Эндпоинт не существует */
        DOES_NOT_EXIST
    }
}
