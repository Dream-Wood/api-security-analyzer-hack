package webui.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import webui.model.AnalysisRequest;
import webui.model.AnalysisResponse;
import webui.service.AnalysisService;

import java.util.Map;

/**
 * Controller for analysis operations.
 */
@RestController
@RequestMapping("/api/analysis")
public class AnalysisController {

    private final AnalysisService analysisService;

    public AnalysisController(AnalysisService analysisService) {
        this.analysisService = analysisService;
    }

    /**
     * Start a new analysis.
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
     * Get analysis status.
     * GET /api/analysis/{sessionId}/status
     */
    @GetMapping("/{sessionId}/status")
    public ResponseEntity<Map<String, Object>> getStatus(@PathVariable("sessionId") String sessionId) {
        return analysisService.getSession(sessionId)
                .map(session -> ResponseEntity.ok(Map.<String, Object>of(
                        "sessionId", session.getSessionId(),
                        "status", session.getStatus()
                )))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Get analysis logs.
     * GET /api/analysis/{sessionId}/logs
     */
    @GetMapping("/{sessionId}/logs")
    public ResponseEntity<?> getLogs(@PathVariable("sessionId") String sessionId) {
        return analysisService.getSession(sessionId)
                .map(session -> ResponseEntity.ok(session.getLogs()))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Get analysis report.
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
     * Cancel an analysis.
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
}
