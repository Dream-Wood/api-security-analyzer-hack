package webui.model;

import java.util.List;
import java.util.Map;

/**
 * Модель запроса для запуска AsyncAPI анализа безопасности.
 */
public record AsyncAnalysisRequest(
    String specLocation,
    String mode,  // Analysis mode: "static", "active", "both"
    String selectedServer,  // Имя сервера из AsyncAPI спецификации
    Map<String, String> credentials, // username, password, apiKey, etc.
    Map<String, String> protocolProperties, // protocol-specific properties (key-value)
    Map<String, String> sslProperties, // SSL/TLS properties (key-value)
    boolean enableSsl,
    Integer connectionTimeoutMs,
    Integer operationTimeoutMs,
    List<String> enabledScanners, // List of async scanner IDs to enable
    String scanIntensity,  // Scan intensity: "low", "medium", "high", "aggressive"
    Integer maxParallelScans,
    Integer requestDelayMs,
    Integer maxRequestsPerChannel
) {
    public AsyncAnalysisRequest {
        // Default values
        if (mode == null || mode.isEmpty()) {
            mode = "static";
        }
        if (scanIntensity == null || scanIntensity.isEmpty()) {
            scanIntensity = "medium";
        }
        if (connectionTimeoutMs == null) {
            connectionTimeoutMs = 30000; // 30 seconds
        }
        if (operationTimeoutMs == null) {
            operationTimeoutMs = 30000; // 30 seconds
        }
        if (maxParallelScans == null) {
            maxParallelScans = 4;
        }
    }
}
