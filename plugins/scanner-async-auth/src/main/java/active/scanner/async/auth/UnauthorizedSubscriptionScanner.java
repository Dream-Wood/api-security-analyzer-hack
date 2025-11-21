package active.scanner.async.auth;

import active.async.*;
import active.protocol.*;
import active.scanner.ScanContext;
import model.AsyncOperationSpec;
import model.AsyncOperationType;
import model.Severity;

import java.util.Arrays;
import java.util.List;

/**
 * Scanner that detects unauthorized subscription vulnerabilities in AsyncAPI operations.
 *
 * <p>This scanner tests whether SUBSCRIBE operations can be performed without proper
 * authentication, which could lead to unauthorized access to sensitive message streams.
 *
 * <p><b>Test Strategy:</b>
 * <ol>
 *   <li>Identify SUBSCRIBE operations that should require authentication</li>
 *   <li>Attempt to subscribe without providing credentials</li>
 *   <li>Report vulnerability if subscription succeeds</li>
 * </ol>
 *
 * <p><b>Supported Protocols:</b> All async protocols (Kafka, MQTT, WebSocket, AMQP, etc.)
 *
 * <p><b>Example Vulnerability:</b>
 * A Kafka topic containing sensitive user data allows subscription without authentication,
 * exposing PII to unauthorized consumers.
 */
public class UnauthorizedSubscriptionScanner extends AbstractAsyncScanner {

    private static final String SCANNER_NAME = "Unauthorized Subscription Scanner";
    private static final String VERSION = "1.0.0";
    private static final String AUTHOR = "API Security Analyzer Team";

    // Channel patterns that typically contain sensitive data
    private static final List<String> SENSITIVE_PATTERNS = Arrays.asList(
            "user", "account", "payment", "order", "private", "admin", "internal",
            "auth", "credential", "token", "secret", "personal", "profile"
    );

    /**
     * Получить локализованное сообщение из bundle сканера.
     *
     * @param key ключ сообщения
     * @param params параметры для форматирования (опционально)
     * @return локализованное сообщение или ключ если локализация не найдена
     */
    private String getLocalizedMessage(String key, Object... params) {
        try {
            String message = com.apisecurity.analyzer.core.i18n.PluginMessageService.getMessage(
                "asyncauth",
                key,
                getClass().getClassLoader()
            );

            // Если параметры предоставлены, форматируем сообщение
            if (params != null && params.length > 0) {
                message = java.text.MessageFormat.format(message, params);
            }

            return message;
        } catch (Exception e) {
            // Если локализация не работает, возвращаем ключ
            return key;
        }
    }

    public UnauthorizedSubscriptionScanner() {
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
        // Only applicable to SUBSCRIBE operations
        if (operation.getOperationType() != AsyncOperationType.SUBSCRIBE) {
            return false;
        }

        // If operation explicitly requires authentication, it's worth testing
        // to see if the requirement is actually enforced
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
            // Attempt to subscribe without authentication
            boolean subscriptionSucceeded = attemptUnauthenticatedSubscription(
                    client, operation, context);

            if (subscriptionSucceeded) {
                // Vulnerability found!
                boolean isSensitive = isSensitiveChannel(operation.getChannelName());
                Severity severity = isSensitive ? Severity.HIGH : Severity.MEDIUM;

                AsyncVulnerabilityReport vulnerability = createVulnerabilityReport(
                        operation, client, severity, isSensitive);

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
            // If we get an authentication error, that's actually good - it means auth is required
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
     * Attempt to subscribe to a channel without authentication.
     *
     * @param client    the protocol client
     * @param operation the operation to test
     * @param context   scan context
     * @return true if subscription succeeded, false otherwise
     */
    private boolean attemptUnauthenticatedSubscription(
            ProtocolClient client,
            AsyncOperationSpec operation,
            ScanContext context) throws ProtocolException {

        incrementRequestCount();
        applyDelay(context);

        String channel = operation.getChannelName();

        try {
            // Create subscribe request without authentication headers
            ProtocolRequest request = ProtocolRequest.builder()
                    .type(ProtocolRequest.RequestType.SUBSCRIBE)
                    .channel(channel)
                    .timeoutMs(5000) // 5 second timeout
                    .build();

            // Attempt subscription
            ProtocolResponse response = client.send(request);

            // If we got a successful response, the channel allows unauthenticated access
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
     * Check if a channel name suggests it contains sensitive data.
     *
     * @param channelName the channel name
     * @return true if likely sensitive
     */
    private boolean isSensitiveChannel(String channelName) {
        String lowerName = channelName.toLowerCase();
        return SENSITIVE_PATTERNS.stream()
                .anyMatch(lowerName::contains);
    }

    /**
     * Create a detailed vulnerability report.
     *
     * @param operation   the vulnerable operation
     * @param client      the protocol client
     * @param severity    vulnerability severity
     * @param isSensitive whether channel is sensitive
     * @return vulnerability report
     */
    private AsyncVulnerabilityReport createVulnerabilityReport(
            AsyncOperationSpec operation,
            ProtocolClient client,
            Severity severity,
            boolean isSensitive) {

        String channelName = operation.getChannelName();

        // Build title
        String title = getLocalizedMessage("vuln.unauthorized_subscription.title", channelName);

        // Build description
        String sensitiveNote = isSensitive ?
                getLocalizedMessage("vuln.unauthorized_subscription.description.sensitive") + " " : "";
        String description = getLocalizedMessage("vuln.unauthorized_subscription.description",
                channelName, sensitiveNote);

        // Build reproduction steps
        String reproductionSteps =
                "1. " + getLocalizedMessage("vuln.unauthorized_subscription.repro.step1",
                        client.getProtocol().toUpperCase()) + "\n" +
                "2. " + getLocalizedMessage("vuln.unauthorized_subscription.repro.step2",
                        channelName) + "\n" +
                "3. " + getLocalizedMessage("vuln.unauthorized_subscription.repro.step3") + "\n" +
                "4. " + getLocalizedMessage("vuln.unauthorized_subscription.repro.step4");

        // Build protocol metadata
        AsyncVulnerabilityReport.ProtocolMetadata protocolMetadata =
                AsyncVulnerabilityReport.ProtocolMetadata.builder()
                        .protocol(client.getProtocol())
                        .protocolVersion(client.getProtocolVersion())
                        .channel(channelName)
                        .build();

        // Build vulnerability report
        return AsyncVulnerabilityReport.builder()
                .type(AsyncVulnerabilityReport.AsyncVulnerabilityType.UNAUTHORIZED_SUBSCRIPTION)
                .severity(severity)
                .operation(operation)
                .protocolMetadata(protocolMetadata)
                .title(title)
                .description(description)
                .reproductionSteps(reproductionSteps)
                .addEvidence("channel", channelName)
                .addEvidence("operationType", operation.getOperationType().toString())
                .addEvidence("requiresAuth", operation.requiresAuthentication())
                .addEvidence("isSensitive", isSensitive)
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
