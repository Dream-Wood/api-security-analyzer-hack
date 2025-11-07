package webui.model;

import java.util.List;

/**
 * Информация о сканере уязвимостей для пользовательского интерфейса.
 */
public record ScannerInfo(
    String id,
    String name,
    String description,
    List<String> detectedVulnerabilities,
    boolean enabled,
    String category // e.g., "Authentication", "Injection", "Configuration"
) {
}
