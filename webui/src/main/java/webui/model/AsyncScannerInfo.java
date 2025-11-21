package webui.model;

import java.util.List;

/**
 * Информация об AsyncAPI сканере безопасности.
 */
public record AsyncScannerInfo(
    String id,
    String name,
    String description,
    List<String> supportedProtocols,
    boolean enabledByDefault
) {
}
