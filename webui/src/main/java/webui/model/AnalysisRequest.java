package webui.model;

import java.util.List;

/**
 * Request model for starting an analysis.
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
    List<String> enabledScanners // List of scanner IDs to enable (null = all enabled)
) {
    public AnalysisRequest {
        // Default values
        if (mode == null || mode.isEmpty()) {
            mode = "static";
        }
        if (cryptoProtocol == null || cryptoProtocol.isEmpty()) {
            cryptoProtocol = "standard";
        }
    }
}
