package webui.model;

import java.util.List;

/**
 * Information about a vulnerability scanner for the UI.
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
