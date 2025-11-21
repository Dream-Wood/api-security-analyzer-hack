package webui.controller;

import com.apisecurity.analyzer.core.i18n.LocaleManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
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
     * Поддерживает заголовок Accept-Language для локализации (ru, en)
     */
    @GetMapping
    public List<ScannerInfo> getAllScanners(
            @RequestHeader(value = "Accept-Language", required = false, defaultValue = "en") String acceptLanguage
    ) {
        // Extract first language code from Accept-Language header (e.g., "ru-RU,ru" -> "ru")
        String languageCode = acceptLanguage.split("[,;-]")[0].trim().toLowerCase();

        // Set locale for this request
        try {
            LocaleManager.setCurrentLocale(languageCode);
        } catch (IllegalArgumentException e) {
            // If unsupported language, fallback to English
            LocaleManager.setCurrentLocale("en");
        }

        return analysisService.getAvailableScanners();
    }
}
