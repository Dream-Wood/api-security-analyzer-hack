package webui.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import webui.model.ScannerInfo;
import webui.service.AnalysisService;

import java.util.List;

/**
 * Контроллер для эндпоинтов получения информации о сканерах.
 */
@RestController
@RequestMapping("/api/scanners")
public class ScannerController {

    private final AnalysisService analysisService;

    public ScannerController(AnalysisService analysisService) {
        this.analysisService = analysisService;
    }

    /**
     * Получение списка всех доступных сканеров.
     * GET /api/scanners
     */
    @GetMapping
    public List<ScannerInfo> getAllScanners() {
        return analysisService.getAvailableScanners();
    }
}
