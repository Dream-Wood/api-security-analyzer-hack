package webui.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import webui.model.ScannerInfo;
import webui.service.AnalysisService;

import java.util.List;

/**
 * Controller for scanner information endpoints.
 */
@RestController
@RequestMapping("/api/scanners")
public class ScannerController {

    private final AnalysisService analysisService;

    public ScannerController(AnalysisService analysisService) {
        this.analysisService = analysisService;
    }

    /**
     * Get all available scanners.
     * GET /api/scanners
     */
    @GetMapping
    public List<ScannerInfo> getAllScanners() {
        return analysisService.getAvailableScanners();
    }
}
