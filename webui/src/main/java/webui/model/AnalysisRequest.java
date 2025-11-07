package webui.model;

import java.util.List;

/**
 * Модель запроса для запуска анализа безопасности.
 */
public record AnalysisRequest(
    String specLocation,
    String mode,
    String baseUrl,
    String authHeader,
    String cryptoProtocol,
    boolean verifySsl,
    String gostPfxPath,
    String gostPfxPassword,
    boolean gostPfxResource,
    boolean verbose,
    boolean noFuzzing,
    boolean autoAuth,
    boolean createTestUsers,
    Integer maxParallelScans,
    List<String> enabledScanners, // List of scanner IDs to enable (null = all enabled)
    String scanIntensity,  // Scan intensity: "low", "medium", "high", "aggressive"
    Integer requestDelayMs, // Custom request delay in ms (overrides intensity default)
    List<UserCredentials> testUsers // List of test user credentials for BOLA/privilege testing
) {
    public AnalysisRequest {
        // Default values
        if (mode == null || mode.isEmpty()) {
            mode = "static";
        }
        if (cryptoProtocol == null || cryptoProtocol.isEmpty()) {
            cryptoProtocol = "standard";
        }
        if (scanIntensity == null || scanIntensity.isEmpty()) {
            scanIntensity = "medium";
        }
    }
}
