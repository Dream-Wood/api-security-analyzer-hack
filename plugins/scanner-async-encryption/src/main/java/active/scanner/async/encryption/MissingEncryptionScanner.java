package active.scanner.async.encryption;

import active.async.*;
import active.protocol.*;
import active.scanner.ScanContext;
import model.AsyncOperationSpec;
import model.Severity;

import java.util.*;

/**
 * Scanner that detects use of unencrypted protocols in AsyncAPI.
 *
 * <p>This scanner checks if AsyncAPI operations use unencrypted protocols which
 * expose message content to eavesdropping and man-in-the-middle attacks.
 *
 * <p><b>Detected Issues:</b>
 * <ul>
 *   <li>WebSocket (ws) instead of WebSocket Secure (wss)</li>
 *   <li>MQTT without TLS (mqtt instead of mqtts)</li>
 *   <li>Kafka without SSL/TLS encryption</li>
 *   <li>AMQP without TLS (amqp instead of amqps)</li>
 *   <li>HTTP instead of HTTPS for message delivery</li>
 * </ul>
 *
 * <p><b>Test Strategy:</b>
 * <ol>
 *   <li>Analyze server URL and protocol specification</li>
 *   <li>Check if secure version of protocol is used</li>
 *   <li>Report vulnerability if unencrypted protocol detected</li>
 * </ol>
 *
 * <p><b>Supported Protocols:</b> All async protocols
 */
public class MissingEncryptionScanner extends AbstractAsyncScanner {

    private static final String SCANNER_NAME = "Missing Encryption Scanner";
    private static final String VERSION = "1.0.0";
    private static final String AUTHOR = "API Security Analyzer Team";

    // Map of insecure protocols to their secure equivalents
    private static final Map<String, String> PROTOCOL_MAPPING = new HashMap<>();

    static {
        PROTOCOL_MAPPING.put("ws", "wss");
        PROTOCOL_MAPPING.put("mqtt", "mqtts");
        PROTOCOL_MAPPING.put("amqp", "amqps");
        PROTOCOL_MAPPING.put("http", "https");
        PROTOCOL_MAPPING.put("kafka", "kafka+ssl");
        PROTOCOL_MAPPING.put("stomp", "stomps");
        PROTOCOL_MAPPING.put("redis", "rediss");
    }

    // Indicators in URLs/configs that suggest missing encryption
    private static final Set<String> INSECURE_URL_PATTERNS = new HashSet<>(Arrays.asList(
        "://localhost",
        "://127.0.0.1",
        "://10.",
        "://172.",
        "://192.168"
    ));

    /**
     * Get localized message from scanner bundle.
     */
    private String getLocalizedMessage(String key, Object... params) {
        try {
            String message = com.apisecurity.analyzer.core.i18n.PluginMessageService.getMessage(
                "asyncencryption",
                key,
                getClass().getClassLoader()
            );

            if (params != null && params.length > 0) {
                message = java.text.MessageFormat.format(message, params);
            }

            return message;
        } catch (Exception e) {
            return key;
        }
    }

    public MissingEncryptionScanner() {
        super(SCANNER_NAME);
    }

    @Override
    public String getDescription() {
        return getLocalizedMessage("scanner.description");
    }

    @Override
    public List<String> getSupportedProtocols() {
        return Arrays.asList("*");
    }

    @Override
    public boolean isApplicable(AsyncOperationSpec operation) {
        // Always applicable - we check protocol security for all operations
        return true;
    }

    @Override
    protected AsyncScanResult performScan(AsyncOperationSpec operation,
                                         ProtocolClient client,
                                         ScanContext context) throws ProtocolException {

        debug(getLocalizedMessage("log.scanning_operation",
                operation.getChannelName()));

        AsyncScanResult.Builder resultBuilder = createResultBuilder(operation);
        long startTime = System.currentTimeMillis();

        // Check protocol security
        String protocol = client.getProtocol().toLowerCase();
        boolean isInsecure = PROTOCOL_MAPPING.containsKey(protocol);

        if (isInsecure) {
            String secureAlternative = PROTOCOL_MAPPING.get(protocol);

            // Determine severity based on context
            Severity severity = determineSeverity(operation, context, protocol);

            AsyncVulnerabilityReport vulnerability = createVulnerabilityReport(
                    operation, client, protocol, secureAlternative, severity);

            resultBuilder.addVulnerability(vulnerability);

            info(getLocalizedMessage("log.found_vulnerability",
                    protocol, operation.getChannelName()));
        } else {
            debug(getLocalizedMessage("log.secure_protocol",
                    protocol, operation.getChannelName()));
        }

        long duration = System.currentTimeMillis() - startTime;
        return resultBuilder
                .success(true)
                .durationMs(duration)
                .build();
    }

    /**
     * Determine severity based on context and data sensitivity.
     */
    private Severity determineSeverity(AsyncOperationSpec operation,
                                      ScanContext context,
                                      String protocol) {

        String channelName = operation.getChannelName().toLowerCase();

        // Critical if handling sensitive data
        if (channelName.contains("payment") ||
            channelName.contains("credential") ||
            channelName.contains("password") ||
            channelName.contains("auth") ||
            channelName.contains("token")) {
            return Severity.CRITICAL;
        }

        // High if handling user data
        if (channelName.contains("user") ||
            channelName.contains("account") ||
            channelName.contains("personal") ||
            channelName.contains("profile")) {
            return Severity.HIGH;
        }

        // Check if URL suggests production environment
        if (context != null) {
            // In production environments, lack of encryption is more severe
            // For now, default to MEDIUM for other cases
        }

        return Severity.MEDIUM;
    }

    /**
     * Create vulnerability report for missing encryption.
     */
    private AsyncVulnerabilityReport createVulnerabilityReport(
            AsyncOperationSpec operation,
            ProtocolClient client,
            String insecureProtocol,
            String secureAlternative,
            Severity severity) {

        String channelName = operation.getChannelName();

        String title = getLocalizedMessage("vuln.missing_encryption.title",
                insecureProtocol.toUpperCase(), channelName);

        String description = getLocalizedMessage("vuln.missing_encryption.description",
                channelName, insecureProtocol.toUpperCase(), secureAlternative.toUpperCase());

        String reproductionSteps =
                "1. " + getLocalizedMessage("vuln.missing_encryption.repro.step1",
                        insecureProtocol.toUpperCase()) + "\n" +
                "2. " + getLocalizedMessage("vuln.missing_encryption.repro.step2",
                        channelName) + "\n" +
                "3. " + getLocalizedMessage("vuln.missing_encryption.repro.step3") + "\n" +
                "4. " + getLocalizedMessage("vuln.missing_encryption.repro.step4",
                        secureAlternative.toUpperCase());

        AsyncVulnerabilityReport.ProtocolMetadata protocolMetadata =
                AsyncVulnerabilityReport.ProtocolMetadata.builder()
                        .protocol(insecureProtocol)
                        .protocolVersion(client.getProtocolVersion())
                        .channel(channelName)
                        .build();

        AsyncVulnerabilityReport.Builder builder = AsyncVulnerabilityReport.builder()
                .type(AsyncVulnerabilityReport.AsyncVulnerabilityType.MISSING_ENCRYPTION)
                .severity(severity)
                .operation(operation)
                .protocolMetadata(protocolMetadata)
                .title(title)
                .description(description)
                .reproductionSteps(reproductionSteps)
                .addEvidence("channel", channelName)
                .addEvidence("insecureProtocol", insecureProtocol)
                .addEvidence("secureAlternative", secureAlternative)
                .addEvidence("operationType", operation.getOperationType().toString());

        // Add recommendations
        for (int i = 1; i <= 5; i++) {
            builder.addRecommendation(getLocalizedMessage("vuln.recommendation" + i,
                    secureAlternative.toUpperCase()));
        }

        return builder.build();
    }

    @Override
    public String getVersion() {
        return VERSION;
    }

    @Override
    public String getAuthor() {
        return AUTHOR;
    }

    @Override
    public boolean isEnabledByDefault() {
        return true;
    }
}
