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
    String serverIp,        // Server IP address for GOST TLS bypass (IP+SNI technique)
    String sniHostname,     // SNI hostname for GOST TLS bypass (hostname from certificate SAN)
    boolean verbose,
    boolean noFuzzing,
    boolean autoAuth,
    boolean createTestUsers,
    Integer maxParallelScans,
    List<String> enabledScanners, // List of scanner IDs to enable (null = all enabled)
    String scanIntensity,  // Scan intensity: "low", "medium", "high", "aggressive"
    Integer requestDelayMs, // Custom request delay in ms (overrides intensity default)
    List<UserCredentials> testUsers, // List of test user credentials for BOLA/privilege testing
    // Discovery options
    boolean enableDiscovery,  // Enable endpoint discovery
    String discoveryStrategy, // Discovery strategy: "none", "top-down", "bottom-up", "hybrid"
    Integer discoveryMaxDepth, // Maximum depth for discovery (default: 5)
    Integer discoveryMaxRequests, // Maximum total requests for discovery (default: 1000)
    boolean discoveryFastCancel, // Stop immediately when dangerous endpoint found
    String wordlistDir // Directory with wordlist files (default: ./wordlists)
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
        if (discoveryStrategy == null || discoveryStrategy.isEmpty()) {
            discoveryStrategy = "none";
        }
    }
}
