package webui.controller;

import com.apisecurity.analyzer.core.i18n.LocaleManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import report.PdfReporter;
import report.ReportFormat;
import report.Reporter;
import report.ReporterFactory;
import util.SpecTypeDetector;
import webui.model.*;
import webui.service.AnalysisService;
import webui.util.ReportLocalizer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Контроллер для операций анализа безопасности API.
 */
@RestController
@RequestMapping("/api/analysis")
public class AnalysisController {
    private static final Logger logger = LoggerFactory.getLogger(AnalysisController.class);

    private final AnalysisService analysisService;

    public AnalysisController(AnalysisService analysisService) {
        this.analysisService = analysisService;
    }

    /**
     * Запуск нового анализа.
     * POST /api/analysis/start
     */
    @PostMapping("/start")
    public ResponseEntity<AnalysisResponse> startAnalysis(@RequestBody AnalysisRequest request) {
        try {
            String sessionId = analysisService.startAnalysis(request);
            return ResponseEntity.ok(AnalysisResponse.success(sessionId, "Analysis started"));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(AnalysisResponse.error("Failed to start analysis: " + e.getMessage()));
        }
    }

    /**
     * Получение полной информации о сессии анализа, включая прогресс.
     * GET /api/analysis/{sessionId}
     */
    @GetMapping("/{sessionId}")
    public ResponseEntity<Map<String, Object>> getSession(
            @PathVariable("sessionId") String sessionId,
            @RequestHeader(value = "Accept-Language", required = false, defaultValue = "en") String acceptLanguage) {

        // Устанавливаем locale из Accept-Language header
        setLocaleFromHeader(acceptLanguage);

        return analysisService.getSession(sessionId)
                .<ResponseEntity<Map<String, Object>>>map(session -> {
                    Map<String, Object> response = new HashMap<>();
                    response.put("sessionId", session.getSessionId());
                    response.put("status", session.getStatus());
                    response.put("logs", session.getLogs());

                    // Локализуем report перед отправкой
                    Object rawReport = session.getReport() != null ? session.getReport() : Map.of();
                    Map<String, Object> localizedReport = ReportLocalizer.localizeReport(rawReport);
                    response.put("report", localizedReport);

                    response.put("currentStep", session.getCurrentStep());
                    response.put("totalSteps", session.getTotalSteps());
                    response.put("progressPercentage", session.getProgressPercentage());
                    response.put("estimatedTimeRemaining", session.getEstimatedTimeRemaining());
                    response.put("currentPhase", session.getCurrentPhase());
                    response.put("currentEndpoint", session.getCurrentEndpoint());
                    response.put("currentScanner", session.getCurrentScanner());
                    response.put("totalVulnerabilitiesFound", session.getTotalVulnerabilitiesFound());
                    return ResponseEntity.ok(response);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Получение статуса анализа.
     * GET /api/analysis/{sessionId}/status
     */
    @GetMapping("/{sessionId}/status")
    public ResponseEntity<Map<String, Object>> getStatus(@PathVariable("sessionId") String sessionId) {
        return analysisService.getSession(sessionId)
                .<ResponseEntity<Map<String, Object>>>map(session -> ResponseEntity.ok(Map.<String, Object>of(
                        "sessionId", session.getSessionId(),
                        "status", session.getStatus()
                )))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Получение логов анализа.
     * GET /api/analysis/{sessionId}/logs
     */
    @GetMapping("/{sessionId}/logs")
    public ResponseEntity<?> getLogs(@PathVariable("sessionId") String sessionId) {
        return analysisService.getSession(sessionId)
                .map(session -> ResponseEntity.ok(session.getLogs()))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Получение отчета анализа.
     * GET /api/analysis/{sessionId}/report
     */
    @GetMapping("/{sessionId}/report")
    public ResponseEntity<?> getReport(
            @PathVariable("sessionId") String sessionId,
            @RequestHeader(value = "Accept-Language", required = false, defaultValue = "en") String acceptLanguage) {

        // Устанавливаем locale из Accept-Language header
        setLocaleFromHeader(acceptLanguage);

        return analysisService.getSession(sessionId)
                .map(session -> {
                    if (session.getReport() == null) {
                        return ResponseEntity.ok(Map.<String, Object>of(
                                "status", session.getStatus(),
                                "message", "Report not available yet"
                        ));
                    } else {
                        // Локализуем report перед отправкой
                        Map<String, Object> localizedReport = ReportLocalizer.localizeReport(session.getReport());
                        return ResponseEntity.ok(localizedReport);
                    }
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Отмена анализа.
     * POST /api/analysis/{sessionId}/cancel
     */
    @PostMapping("/{sessionId}/cancel")
    public ResponseEntity<Map<String, String>> cancelAnalysis(@PathVariable("sessionId") String sessionId) {
        boolean cancelled = analysisService.cancelAnalysis(sessionId);

        if (cancelled) {
            return ResponseEntity.ok(Map.of("message", "Analysis cancelled"));
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Скачивание отчета анализа в указанном формате.
     * GET /api/analysis/{sessionId}/download?format={format}
     */
    @GetMapping("/{sessionId}/download")
    public ResponseEntity<Resource> downloadReport(
            @PathVariable("sessionId") String sessionId,
            @RequestParam(value = "format", defaultValue = "JSON") String formatStr) {

        var sessionOpt = analysisService.getSession(sessionId);

        if (sessionOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        var session = sessionOpt.get();

        if (session.getReport() == null) {
            return ResponseEntity.notFound().build();
        }

        try {
            ReportFormat format = ReportFormat.valueOf(formatStr.toUpperCase());
            String filename = "analysis-report-" + sessionId;
            MediaType mediaType;
            byte[] reportData;

            switch (format) {
                case PDF -> {
                    filename += ".pdf";
                    mediaType = MediaType.APPLICATION_PDF;

                    PdfReporter pdfReporter = new PdfReporter();
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    pdfReporter.generateToOutputStream(session.getReport(), baos);
                    reportData = baos.toByteArray();
                }
                case JSON -> {
                    filename += ".json";
                    mediaType = MediaType.APPLICATION_JSON;

                    Reporter jsonReporter = ReporterFactory.createReporter(ReportFormat.JSON);
                    StringWriter stringWriter = new StringWriter();
                    PrintWriter printWriter = new PrintWriter(stringWriter);
                    jsonReporter.generate(session.getReport(), printWriter);
                    printWriter.flush();
                    reportData = stringWriter.toString().getBytes();
                }
                default -> {
                    filename += ".txt";
                    mediaType = MediaType.TEXT_PLAIN;

                    Reporter reporter = ReporterFactory.createReporter(format);
                    StringWriter stringWriter = new StringWriter();
                    PrintWriter printWriter = new PrintWriter(stringWriter);
                    reporter.generate(session.getReport(), printWriter);
                    printWriter.flush();
                    reportData = stringWriter.toString().getBytes();
                }
            }

            ByteArrayResource resource = new ByteArrayResource(reportData);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment; filename=\"" + filename + "\"")
                    .contentType(mediaType)
                    .contentLength(reportData.length)
                    .body(resource);

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        } catch (Exception e) {
            logger.error("Error generating report download for session {}", sessionId, e);
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * Загрузка файла спецификации API.
     * POST /api/analysis/upload-file
     */
    @PostMapping("/upload-file")
    public ResponseEntity<Map<String, String>> uploadFile(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "No file provided"));
        }

        try {
            // Create temp directory if it doesn't exist
            Path uploadDir = Paths.get(System.getProperty("java.io.tmpdir"), "api-security-analyzer-uploads");
            if (!Files.exists(uploadDir)) {
                Files.createDirectories(uploadDir);
            }

            // Generate unique filename with timestamp
            String originalFilename = file.getOriginalFilename();
            if (originalFilename == null || originalFilename.isEmpty()) {
                originalFilename = "uploaded-spec.yaml";
            }

            // Sanitize filename
            String sanitizedFilename = originalFilename.replaceAll("[^a-zA-Z0-9._-]", "_");
            String uniqueFilename = System.currentTimeMillis() + "-" + sanitizedFilename;
            Path targetPath = uploadDir.resolve(uniqueFilename);

            // Save file
            Files.copy(file.getInputStream(), targetPath, StandardCopyOption.REPLACE_EXISTING);

            // Return the absolute path
            String absolutePath = targetPath.toAbsolutePath().toString();

            Map<String, String> response = new HashMap<>();
            response.put("path", absolutePath);
            response.put("filename", sanitizedFilename);
            response.put("size", String.valueOf(file.getSize()));

            return ResponseEntity.ok(response);

        } catch (IOException e) {
            return ResponseEntity.status(500)
                    .body(Map.of("error", "Failed to upload file: " + e.getMessage()));
        }
    }

    /**
     * Определение типа спецификации (OpenAPI vs AsyncAPI).
     * GET /api/analysis/detect-spec-type?path={path}
     */
    @GetMapping("/detect-spec-type")
    public ResponseEntity<Map<String, String>> detectSpecType(@RequestParam("path") String path) {
        try {
            SpecTypeDetector.DetectionResult result =
                SpecTypeDetector.detectTypeWithVersion(path);

            Map<String, String> response = new HashMap<>();
            if (result.isSuccess()) {
                response.put("type", result.getType().name().toLowerCase());
                response.put("version", result.getVersion());
                response.put("displayName", result.getType().getDisplayName());
                response.put("supportsActiveAnalysis",
                    String.valueOf(result.getType().supportsActiveAnalysis()));
            } else {
                response.put("type", "unknown");
                response.put("error", result.getErrorMessage());
            }

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> response = new HashMap<>();
            response.put("type", "unknown");
            response.put("error", e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Получение информации об AsyncAPI спецификации.
     * GET /api/analysis/asyncapi/info?path={path}
     * Всегда возвращает 200 OK с результатом - ошибки валидации содержатся в поле validationMessages.
     */
    @GetMapping("/asyncapi/info")
    public ResponseEntity<AsyncApiInfo> getAsyncApiInfo(@RequestParam("path") String path) {
        AsyncApiInfo info = analysisService.getAsyncApiInfo(path);
        return ResponseEntity.ok(info);
    }

    /**
     * Запуск анализа AsyncAPI спецификации.
     * POST /api/analysis/asyncapi/start
     */
    @PostMapping("/asyncapi/start")
    public ResponseEntity<AnalysisResponse> startAsyncAnalysis(@RequestBody AsyncAnalysisRequest request) {
        try {
            String sessionId = analysisService.startAsyncAnalysis(request);
            return ResponseEntity.ok(AnalysisResponse.success(sessionId, "AsyncAPI analysis started"));
        } catch (Exception e) {
            logger.error("Error starting AsyncAPI analysis", e);
            return ResponseEntity.badRequest()
                    .body(AnalysisResponse.error("Failed to start AsyncAPI analysis: " + e.getMessage()));
        }
    }

    /**
     * Пинг URL для проверки доступности сервера.
     * GET /api/analysis/ping?url={url}
     */
    @GetMapping("/ping")
    public ResponseEntity<Map<String, Object>> pingServer(@RequestParam("url") String url) {
        Map<String, Object> response = new HashMap<>();
        response.put("url", url);

        try {
            // Handle WebSocket URLs - try TCP connection instead of HTTP HEAD
            if (url.startsWith("ws://") || url.startsWith("wss://")) {
                return pingWebSocket(url, response);
            }

            // Validate URL format
            URI uri = URI.create(url);
            if (uri.getScheme() == null || (!uri.getScheme().equals("http") && !uri.getScheme().equals("https"))) {
                response.put("available", false);
                response.put("error", "Invalid URL scheme. Must be http, https, ws, or wss.");
                return ResponseEntity.ok(response);
            }

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .timeout(Duration.ofSeconds(10))
                    .method("HEAD", HttpRequest.BodyPublishers.noBody())
                    .header("User-Agent", "API-Security-Analyzer/1.0")
                    .build();

            long startTime = System.currentTimeMillis();
            HttpResponse<Void> httpResponse = client.send(request, HttpResponse.BodyHandlers.discarding());
            long latencyMs = System.currentTimeMillis() - startTime;

            int statusCode = httpResponse.statusCode();
            // Consider any response (even 4xx/5xx) as "server is reachable"
            boolean available = statusCode > 0;

            response.put("available", available);
            response.put("latencyMs", latencyMs);
            response.put("statusCode", statusCode);

            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            response.put("available", false);
            response.put("error", "Invalid URL format: " + e.getMessage());
            return ResponseEntity.ok(response);
        } catch (java.net.ConnectException e) {
            response.put("available", false);
            response.put("error", "Connection refused");
            return ResponseEntity.ok(response);
        } catch (java.net.http.HttpTimeoutException e) {
            response.put("available", false);
            response.put("error", "Connection timeout");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("available", false);
            response.put("error", e.getMessage());
            return ResponseEntity.ok(response);
        }
    }

    /**
     * Ping WebSocket server using TCP socket connection.
     */
    private ResponseEntity<Map<String, Object>> pingWebSocket(String url, Map<String, Object> response) {
        try {
            // Parse ws:// or wss:// URL
            String cleanUrl = url.replaceFirst("wss?://", "");
            String host;
            int port;

            if (cleanUrl.contains(":")) {
                String[] parts = cleanUrl.split(":");
                host = parts[0];
                // Handle path in URL (e.g., host:port/path)
                String portPart = parts[1].split("/")[0];
                port = Integer.parseInt(portPart);
            } else {
                // Handle path in URL
                host = cleanUrl.split("/")[0];
                port = url.startsWith("wss://") ? 443 : 80;
            }

            long startTime = System.currentTimeMillis();

            // Try TCP connection to check if port is open
            try (java.net.Socket socket = new java.net.Socket()) {
                socket.connect(new java.net.InetSocketAddress(host, port), 10000);
                long latencyMs = System.currentTimeMillis() - startTime;

                response.put("available", true);
                response.put("latencyMs", latencyMs);
                response.put("statusCode", 0); // No HTTP status for WebSocket
                response.put("protocol", "websocket");
                return ResponseEntity.ok(response);
            }

        } catch (java.net.ConnectException e) {
            response.put("available", false);
            response.put("error", "Connection refused - server may not be running");
            return ResponseEntity.ok(response);
        } catch (java.net.SocketTimeoutException e) {
            response.put("available", false);
            response.put("error", "Connection timeout");
            return ResponseEntity.ok(response);
        } catch (java.net.UnknownHostException e) {
            response.put("available", false);
            response.put("error", "Unknown host: " + e.getMessage());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("available", false);
            response.put("error", e.getMessage());
            return ResponseEntity.ok(response);
        }
    }

    /**
     * Пинг нескольких URL одновременно.
     * POST /api/analysis/ping-batch
     */
    @PostMapping("/ping-batch")
    public ResponseEntity<Map<String, Object>> pingServers(@RequestBody List<String> urls) {
        Map<String, Object> results = new HashMap<>();

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        for (String url : urls) {
            Map<String, Object> pingResult = new HashMap<>();
            pingResult.put("url", url);

            try {
                URI uri = URI.create(url);
                if (uri.getScheme() == null || (!uri.getScheme().equals("http") && !uri.getScheme().equals("https"))) {
                    pingResult.put("available", false);
                    pingResult.put("error", "Invalid URL scheme");
                    results.put(url, pingResult);
                    continue;
                }

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(uri)
                        .timeout(Duration.ofSeconds(10))
                        .method("HEAD", HttpRequest.BodyPublishers.noBody())
                        .header("User-Agent", "API-Security-Analyzer/1.0")
                        .build();

                long startTime = System.currentTimeMillis();
                HttpResponse<Void> httpResponse = client.send(request, HttpResponse.BodyHandlers.discarding());
                long latencyMs = System.currentTimeMillis() - startTime;

                pingResult.put("available", true);
                pingResult.put("latencyMs", latencyMs);
                pingResult.put("statusCode", httpResponse.statusCode());

            } catch (Exception e) {
                pingResult.put("available", false);
                pingResult.put("error", e.getMessage() != null ? e.getMessage() : "Connection failed");
            }

            results.put(url, pingResult);
        }

        return ResponseEntity.ok(results);
    }

    /**
     * Вспомогательный метод для установки locale из Accept-Language header.
     */
    private void setLocaleFromHeader(String acceptLanguage) {
        if (acceptLanguage == null || acceptLanguage.isBlank()) {
            return;
        }

        // Извлекаем код языка (до первого дефиса, запятой или точки с запятой)
        String languageCode = acceptLanguage.split("[,;-]")[0].trim().toLowerCase();

        try {
            LocaleManager.setCurrentLocale(languageCode);
        } catch (IllegalArgumentException e) {
            logger.warn("Invalid language code in Accept-Language header: {}", acceptLanguage);
            LocaleManager.setCurrentLocale("en");
        }
    }
}
