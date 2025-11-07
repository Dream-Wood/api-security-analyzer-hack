package webui.controller;

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
import webui.model.AnalysisRequest;
import webui.model.AnalysisResponse;
import webui.service.AnalysisService;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
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
    public ResponseEntity<Map<String, Object>> getSession(@PathVariable("sessionId") String sessionId) {
        return analysisService.getSession(sessionId)
                .<ResponseEntity<Map<String, Object>>>map(session -> {
                    Map<String, Object> response = new HashMap<>();
                    response.put("sessionId", session.getSessionId());
                    response.put("status", session.getStatus());
                    response.put("logs", session.getLogs());
                    response.put("report", session.getReport() != null ? session.getReport() : Map.of());
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
    public ResponseEntity<?> getReport(@PathVariable("sessionId") String sessionId) {
        return analysisService.getSession(sessionId)
                .map(session -> {
                    if (session.getReport() == null) {
                        return ResponseEntity.ok(Map.<String, Object>of(
                                "status", session.getStatus(),
                                "message", "Report not available yet"
                        ));
                    } else {
                        return ResponseEntity.ok(session.getReport());
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
}
