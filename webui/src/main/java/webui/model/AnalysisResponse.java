package webui.model;

/**
 * Response model for analysis operations.
 */
public record AnalysisResponse(
    String sessionId,
    String status,
    String message,
    Object report // AnalysisReport serialized to JSON
) {
    public static AnalysisResponse success(String sessionId, String message) {
        return new AnalysisResponse(sessionId, "success", message, null);
    }

    public static AnalysisResponse error(String message) {
        return new AnalysisResponse(null, "error", message, null);
    }

    public static AnalysisResponse withReport(String sessionId, Object report) {
        return new AnalysisResponse(sessionId, "completed", "Analysis completed", report);
    }
}
