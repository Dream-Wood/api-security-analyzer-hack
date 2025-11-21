package active.discovery.model;

import active.model.ApiEndpoint;
import model.Severity;

import java.time.Instant;
import java.util.*;

/**
 * Результат обнаружения незадокументированного эндпоинта.
 */
public final class DiscoveryResult {
    private final ApiEndpoint endpoint;
    private final int statusCode;
    private final String responseBody;
    private final Map<String, String> responseHeaders;
    private final long responseTimeMs;
    private final DiscoveryMethod discoveryMethod;
    private final Severity severity;
    private final String reason;
    private final Instant discoveredAt;
    private final Map<String, Object> metadata;

    private DiscoveryResult(Builder builder) {
        this.endpoint = Objects.requireNonNull(builder.endpoint, "endpoint cannot be null");
        this.statusCode = builder.statusCode;
        this.responseBody = builder.responseBody;
        this.responseHeaders = builder.responseHeaders != null
            ? Collections.unmodifiableMap(new LinkedHashMap<>(builder.responseHeaders))
            : Collections.emptyMap();
        this.responseTimeMs = builder.responseTimeMs;
        this.discoveryMethod = builder.discoveryMethod != null ? builder.discoveryMethod : DiscoveryMethod.TOP_DOWN;
        this.severity = builder.severity != null ? builder.severity : calculateSeverity(builder.statusCode);
        this.reason = builder.reason;
        this.discoveredAt = builder.discoveredAt != null ? builder.discoveredAt : Instant.now();
        this.metadata = builder.metadata != null
            ? Collections.unmodifiableMap(new HashMap<>(builder.metadata))
            : Collections.emptyMap();
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Автоматически определяет severity на основе статус кода.
     */
    private static Severity calculateSeverity(int statusCode) {
        if (statusCode >= 200 && statusCode < 300) {
            return Severity.HIGH; // Незадокументированный рабочий эндпоинт
        } else if (statusCode == 401 || statusCode == 403) {
            return Severity.CRITICAL; // Требует аутентификации - очень подозрительно
        } else if (statusCode == 405) {
            return Severity.MEDIUM; // Эндпоинт существует, но метод не тот
        } else if (statusCode >= 500) {
            return Severity.MEDIUM; // Может существовать, но ошибка
        }
        return Severity.LOW;
    }

    public ApiEndpoint getEndpoint() {
        return endpoint;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getResponseBody() {
        return responseBody;
    }

    public Map<String, String> getResponseHeaders() {
        return responseHeaders;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    public DiscoveryMethod getDiscoveryMethod() {
        return discoveryMethod;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getReason() {
        return reason;
    }

    public Instant getDiscoveredAt() {
        return discoveredAt;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    /**
     * Является ли результат потенциально опасным (CRITICAL или HIGH).
     */
    public boolean isDangerous() {
        return severity == Severity.CRITICAL || severity == Severity.HIGH;
    }

    @Override
    public String toString() {
        return "DiscoveryResult{" +
               "endpoint=" + endpoint +
               ", status=" + statusCode +
               ", method=" + discoveryMethod +
               ", severity=" + severity +
               ", time=" + responseTimeMs + "ms" +
               '}';
    }

    /**
     * Метод обнаружения эндпоинта.
     */
    public enum DiscoveryMethod {
        /** Обнаружен через top-down подход */
        TOP_DOWN,

        /** Обнаружен через bottom-up подход */
        BOTTOM_UP,

        /** Обнаружен через гибридный подход */
        HYBRID,

        /** Обнаружен через словарь */
        WORDLIST
    }

    public static class Builder {
        private ApiEndpoint endpoint;
        private int statusCode;
        private String responseBody;
        private Map<String, String> responseHeaders;
        private long responseTimeMs;
        private DiscoveryMethod discoveryMethod;
        private Severity severity;
        private String reason;
        private Instant discoveredAt;
        private Map<String, Object> metadata;

        public Builder endpoint(ApiEndpoint endpoint) {
            this.endpoint = endpoint;
            return this;
        }

        public Builder statusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        public Builder responseBody(String responseBody) {
            this.responseBody = responseBody;
            return this;
        }

        public Builder responseHeaders(Map<String, String> responseHeaders) {
            this.responseHeaders = new LinkedHashMap<>(responseHeaders);
            return this;
        }

        public Builder addResponseHeader(String key, String value) {
            if (this.responseHeaders == null) {
                this.responseHeaders = new LinkedHashMap<>();
            }
            this.responseHeaders.put(key, value);
            return this;
        }

        public Builder responseTimeMs(long responseTimeMs) {
            this.responseTimeMs = responseTimeMs;
            return this;
        }

        public Builder discoveryMethod(DiscoveryMethod discoveryMethod) {
            this.discoveryMethod = discoveryMethod;
            return this;
        }

        public Builder severity(Severity severity) {
            this.severity = severity;
            return this;
        }

        public Builder reason(String reason) {
            this.reason = reason;
            return this;
        }

        public Builder discoveredAt(Instant discoveredAt) {
            this.discoveredAt = discoveredAt;
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = new HashMap<>(metadata);
            return this;
        }

        public Builder addMetadata(String key, Object value) {
            if (this.metadata == null) {
                this.metadata = new HashMap<>();
            }
            this.metadata.put(key, value);
            return this;
        }

        public DiscoveryResult build() {
            return new DiscoveryResult(this);
        }
    }
}
