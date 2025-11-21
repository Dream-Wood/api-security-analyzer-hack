package active.scanner.async.publish;

import active.async.*;
import active.protocol.*;
import active.scanner.ScanContext;
import model.AsyncOperationSpec;
import model.AsyncOperationType;
import model.Severity;

import java.util.Arrays;
import java.util.List;

/**
 * Scanner that detects unauthorized publish vulnerabilities in AsyncAPI operations.
 *
 * <p>This scanner tests whether PUBLISH operations can be performed without proper
 * authentication, which could lead to message injection, data poisoning, or DoS attacks.
 *
 * <p><b>Test Strategy:</b>
 * <ol>
 *   <li>Identify PUBLISH operations that should require authentication</li>
 *   <li>Attempt to publish messages without providing credentials</li>
 *   <li>Report vulnerability if publishing succeeds</li>
 * </ol>
 *
 * <p><b>Supported Protocols:</b> All async protocols (Kafka, MQTT, WebSocket, AMQP, etc.)
 *
 * <p><b>Example Vulnerability:</b>
 * A Kafka topic for critical events allows unauthenticated publishing, enabling
 * attackers to inject malicious events into the system.
 */
public class UnauthorizedPublishScanner extends AbstractAsyncScanner {

    private static final String SCANNER_NAME = "Unauthorized Publish Scanner";
    private static final String VERSION = "1.0.0";
    private static final String AUTHOR = "API Security Analyzer Team";

    // Channel patterns that typically require strict publish control
    private static final List<String> CRITICAL_PATTERNS = Arrays.asList(
            "order", "payment", "transaction", "admin", "command", "control",
            "auth", "credential", "config", "system", "internal", "critical"
    );

    /**
     * Get localized message from scanner bundle.
     *
     * @param key message key
     * @param params format parameters (optional)
     * @return localized message or key if localization not found
     */
    private String getLocalizedMessage(String key, Object... params) {
        try {
            String message = com.apisecurity.analyzer.core.i18n.PluginMessageService.getMessage(
                "asyncpublish",
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

    public UnauthorizedPublishScanner() {
        super(SCANNER_NAME);
    }

    @Override
    public String getDescription() {
        return getLocalizedMessage("scanner.description");
    }

    @Override
    public List<String> getSupportedProtocols() {
        return Arrays.asList("*"); // Supports all protocols
    }

    @Override
    public boolean isApplicable(AsyncOperationSpec operation) {
        // Only applicable to PUBLISH operations
        if (operation.getOperationType() != AsyncOperationType.PUBLISH) {
            return false;
        }

        // Worth testing if operation requires authentication
        return true;
    }

    @Override
    protected AsyncScanResult performScan(AsyncOperationSpec operation,
                                         ProtocolClient client,
                                         ScanContext context) throws ProtocolException {

        debug(getLocalizedMessage("log.scanning_operation",
                operation.getChannelName(), operation.getOperationType()));

        AsyncScanResult.Builder resultBuilder = createResultBuilder(operation);
        long startTime = System.currentTimeMillis();

        try {
            // Attempt to publish without authentication
            boolean publishSucceeded = attemptUnauthenticatedPublish(
                    client, operation, context);

            if (publishSucceeded) {
                // Vulnerability found!
                boolean isCritical = isCriticalChannel(operation.getChannelName());
                Severity severity = isCritical ? Severity.CRITICAL : Severity.HIGH;

                AsyncVulnerabilityReport vulnerability = createVulnerabilityReport(
                        operation, client, severity, isCritical);

                resultBuilder.addVulnerability(vulnerability);

                info(getLocalizedMessage("log.found_vulnerability",
                        operation.getChannelName(), severity));
            } else {
                debug(getLocalizedMessage("log.requires_auth",
                        operation.getChannelName()));
            }

            long duration = System.currentTimeMillis() - startTime;
            return resultBuilder
                    .success(true)
                    .durationMs(duration)
                    .build();

        } catch (ProtocolException e) {
            // If we get an authentication error, that's good - it means auth is required
            if (e.getErrorType() == ProtocolException.ErrorType.AUTHENTICATION_FAILED) {
                debug(getLocalizedMessage("log.rejected_unauth",
                        operation.getChannelName()));

                long duration = System.currentTimeMillis() - startTime;
                return resultBuilder
                        .success(true)
                        .durationMs(duration)
                        .build();
            }

            throw e;
        }
    }

    /**
     * Attempt to publish to a channel without authentication.
     *
     * @param client    the protocol client
     * @param operation the operation to test
     * @param context   scan context
     * @return true if publish succeeded, false otherwise
     */
    private boolean attemptUnauthenticatedPublish(
            ProtocolClient client,
            AsyncOperationSpec operation,
            ScanContext context) throws ProtocolException {

        incrementRequestCount();
        applyDelay(context);

        String channel = operation.getChannelName();

        try {
            // Create test message payload
            String testPayload = createTestPayload(operation);

            // Create publish request without authentication headers
            ProtocolRequest request = ProtocolRequest.builder()
                    .type(ProtocolRequest.RequestType.PUBLISH)
                    .channel(channel)
                    .payload(testPayload)
                    .timeoutMs(5000) // 5 second timeout
                    .build();

            // Attempt publish
            ProtocolResponse response = client.send(request);

            // If we got a successful response, the channel allows unauthenticated publishing
            return response.isSuccess();

        } catch (ProtocolException e) {
            // If we get an auth error, that's expected and means the channel is secure
            if (e.getErrorType() == ProtocolException.ErrorType.AUTHENTICATION_FAILED) {
                return false;
            }

            // Other errors should be propagated
            throw e;
        }
    }

    /**
     * Create test payload based on operation message schema.
     *
     * @param operation the operation
     * @return test payload as JSON string
     */
    private String createTestPayload(AsyncOperationSpec operation) {
        // Simple test payload that should be harmless
        return "{\"test\":true,\"scanner\":\"api-security-analyzer\",\"timestamp\":\""
                + java.time.Instant.now().toString() + "\"}";
    }

    /**
     * Check if a channel name suggests it's critical for system operation.
     *
     * @param channelName the channel name
     * @return true if likely critical
     */
    private boolean isCriticalChannel(String channelName) {
        String lowerName = channelName.toLowerCase();
        return CRITICAL_PATTERNS.stream()
                .anyMatch(lowerName::contains);
    }

    /**
     * Create a detailed vulnerability report.
     *
     * @param operation   the vulnerable operation
     * @param client      the protocol client
     * @param severity    vulnerability severity
     * @param isCritical  whether channel is critical
     * @return vulnerability report
     */
    private AsyncVulnerabilityReport createVulnerabilityReport(
            AsyncOperationSpec operation,
            ProtocolClient client,
            Severity severity,
            boolean isCritical) {

        String channelName = operation.getChannelName();

        // Build title
        String title = getLocalizedMessage("vuln.unauthorized_publish.title", channelName);

        // Build description
        String criticalNote = isCritical ?
                getLocalizedMessage("vuln.unauthorized_publish.description.critical") + " " : "";
        String description = getLocalizedMessage("vuln.unauthorized_publish.description",
                channelName, criticalNote);

        // Build reproduction steps
        String reproductionSteps =
                "1. " + getLocalizedMessage("vuln.unauthorized_publish.repro.step1",
                        client.getProtocol().toUpperCase()) + "\n" +
                "2. " + getLocalizedMessage("vuln.unauthorized_publish.repro.step2",
                        channelName) + "\n" +
                "3. " + getLocalizedMessage("vuln.unauthorized_publish.repro.step3") + "\n" +
                "4. " + getLocalizedMessage("vuln.unauthorized_publish.repro.step4");

        // Build protocol metadata
        AsyncVulnerabilityReport.ProtocolMetadata protocolMetadata =
                AsyncVulnerabilityReport.ProtocolMetadata.builder()
                        .protocol(client.getProtocol())
                        .protocolVersion(client.getProtocolVersion())
                        .channel(channelName)
                        .build();

        // Build vulnerability report
        return AsyncVulnerabilityReport.builder()
                .type(AsyncVulnerabilityReport.AsyncVulnerabilityType.UNAUTHORIZED_PUBLISH)
                .severity(severity)
                .operation(operation)
                .protocolMetadata(protocolMetadata)
                .title(title)
                .description(description)
                .reproductionSteps(reproductionSteps)
                .addEvidence("channel", channelName)
                .addEvidence("operationType", operation.getOperationType().toString())
                .addEvidence("requiresAuth", operation.requiresAuthentication())
                .addEvidence("isCritical", isCritical)
                .addRecommendation(getLocalizedMessage("vuln.recommendation1"))
                .addRecommendation(getLocalizedMessage("vuln.recommendation2"))
                .addRecommendation(getLocalizedMessage("vuln.recommendation3"))
                .addRecommendation(getLocalizedMessage("vuln.recommendation4"))
                .addRecommendation(getLocalizedMessage("vuln.recommendation5"))
                .build();
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
