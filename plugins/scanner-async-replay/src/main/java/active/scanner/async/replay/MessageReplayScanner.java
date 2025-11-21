package active.scanner.async.replay;

import active.async.*;
import active.protocol.*;
import active.scanner.ScanContext;
import model.AsyncOperationSpec;
import model.AsyncOperationType;
import model.Severity;

import java.util.*;

/**
 * Scanner that detects message replay attack vulnerabilities in AsyncAPI.
 *
 * <p>This scanner tests if systems properly prevent replay attacks by:
 * <ul>
 *   <li>Capturing legitimate messages</li>
 *   <li>Replaying the same message multiple times</li>
 *   <li>Testing if nonces/timestamps are validated</li>
 *   <li>Checking if message IDs are enforced as unique</li>
 * </ul>
 *
 * <p><b>Test Strategy:</b>
 * <ol>
 *   <li>Publish a test message with known content</li>
 *   <li>Immediately replay the same message</li>
 *   <li>Check if the system accepts duplicate messages</li>
 *   <li>Test with modified timestamps to bypass time-based checks</li>
 * </ol>
 *
 * <p><b>Supported Protocols:</b> All async protocols
 *
 * <p><b>Example Attack:</b>
 * An attacker captures a "transfer $1000" message and replays it multiple times
 * to drain victim's account.
 */
public class MessageReplayScanner extends AbstractAsyncScanner {

    private static final String SCANNER_NAME = "Message Replay Scanner";
    private static final String VERSION = "1.0.0";
    private static final String AUTHOR = "API Security Analyzer Team";

    // Number of times to replay the message
    private static final int REPLAY_COUNT = 3;

    /**
     * Get localized message from scanner bundle.
     */
    private String getLocalizedMessage(String key, Object... params) {
        try {
            String message = com.apisecurity.analyzer.core.i18n.PluginMessageService.getMessage(
                "asyncreplay",
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

    public MessageReplayScanner() {
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
        // Applicable to PUBLISH operations (to test replay attacks)
        return operation.getOperationType() == AsyncOperationType.PUBLISH;
    }

    @Override
    protected AsyncScanResult performScan(AsyncOperationSpec operation,
                                         ProtocolClient client,
                                         ScanContext context) throws ProtocolException {

        debug(getLocalizedMessage("log.scanning_operation",
                operation.getChannelName()));

        AsyncScanResult.Builder resultBuilder = createResultBuilder(operation);
        long startTime = System.currentTimeMillis();

        try {
            // Test basic replay attack
            ReplayTestResult basicResult = testBasicReplay(client, operation, context);

            if (basicResult.isVulnerable) {
                AsyncVulnerabilityReport vulnerability = createVulnerabilityReport(
                        operation, client, "basic_replay", basicResult);

                resultBuilder.addVulnerability(vulnerability);

                info(getLocalizedMessage("log.found_vulnerability",
                        operation.getChannelName()));
            }

            // Test replay with modified timestamp
            if (!shouldStopScan(context)) {
                ReplayTestResult timestampResult = testReplayWithModifiedTimestamp(
                        client, operation, context);

                if (timestampResult.isVulnerable) {
                    AsyncVulnerabilityReport vulnerability = createVulnerabilityReport(
                            operation, client, "timestamp_bypass", timestampResult);

                    resultBuilder.addVulnerability(vulnerability);

                    info(getLocalizedMessage("log.found_timestamp_bypass",
                            operation.getChannelName()));
                }
            }

            // Test replay without message ID
            if (!shouldStopScan(context)) {
                ReplayTestResult noIdResult = testReplayWithoutMessageId(
                        client, operation, context);

                if (noIdResult.isVulnerable) {
                    AsyncVulnerabilityReport vulnerability = createVulnerabilityReport(
                            operation, client, "missing_message_id", noIdResult);

                    resultBuilder.addVulnerability(vulnerability);

                    info(getLocalizedMessage("log.found_missing_id",
                            operation.getChannelName()));
                }
            }

        } catch (ProtocolException e) {
            if (e.getErrorType() == ProtocolException.ErrorType.AUTHENTICATION_FAILED) {
                debug(getLocalizedMessage("log.auth_required",
                        operation.getChannelName()));
            } else {
                throw e;
            }
        }

        long duration = System.currentTimeMillis() - startTime;
        return resultBuilder
                .success(true)
                .durationMs(duration)
                .build();
    }

    /**
     * Test basic replay attack - send same message multiple times.
     */
    private ReplayTestResult testBasicReplay(
            ProtocolClient client,
            AsyncOperationSpec operation,
            ScanContext context) throws ProtocolException {

        String channel = operation.getChannelName();
        String messageId = UUID.randomUUID().toString();
        String timestamp = java.time.Instant.now().toString();

        String testMessage = String.format(
            "{\"messageId\":\"%s\",\"timestamp\":\"%s\",\"action\":\"test\",\"scanner\":\"api-security-analyzer\"}",
            messageId, timestamp
        );

        int successCount = 0;
        List<String> responses = new ArrayList<>();

        // Send the same message multiple times
        for (int i = 0; i < REPLAY_COUNT; i++) {
            incrementRequestCount();
            applyDelay(context);

            try {
                ProtocolRequest request = ProtocolRequest.builder()
                        .type(ProtocolRequest.RequestType.PUBLISH)
                        .channel(channel)
                        .payload(testMessage)
                        .timeoutMs(5000)
                        .build();

                ProtocolResponse response = client.send(request);

                if (response.isSuccess()) {
                    successCount++;
                    responses.add("Attempt " + (i + 1) + ": Success");
                } else {
                    responses.add("Attempt " + (i + 1) + ": " + response.getStatusMessage());
                }

            } catch (ProtocolException e) {
                responses.add("Attempt " + (i + 1) + ": " + e.getMessage());
            }
        }

        // If more than one message was accepted, replay is possible
        boolean isVulnerable = successCount > 1;

        return new ReplayTestResult(
            isVulnerable,
            testMessage,
            successCount,
            REPLAY_COUNT,
            responses
        );
    }

    /**
     * Test replay with modified timestamp to bypass time-based checks.
     */
    private ReplayTestResult testReplayWithModifiedTimestamp(
            ProtocolClient client,
            AsyncOperationSpec operation,
            ScanContext context) throws ProtocolException {

        String channel = operation.getChannelName();
        String messageId = UUID.randomUUID().toString();

        int successCount = 0;
        List<String> responses = new ArrayList<>();

        // Send messages with different timestamps but same message ID
        for (int i = 0; i < REPLAY_COUNT; i++) {
            incrementRequestCount();
            applyDelay(context);

            // Create new timestamp for each attempt
            String timestamp = java.time.Instant.now().plusSeconds(i).toString();

            String testMessage = String.format(
                "{\"messageId\":\"%s\",\"timestamp\":\"%s\",\"action\":\"test\"}",
                messageId, timestamp
            );

            try {
                ProtocolRequest request = ProtocolRequest.builder()
                        .type(ProtocolRequest.RequestType.PUBLISH)
                        .channel(channel)
                        .payload(testMessage)
                        .timeoutMs(5000)
                        .build();

                ProtocolResponse response = client.send(request);

                if (response.isSuccess()) {
                    successCount++;
                    responses.add("Timestamp " + i + "s: Success");
                }

            } catch (ProtocolException e) {
                responses.add("Timestamp " + i + "s: " + e.getMessage());
            }
        }

        // If messages with same ID but different timestamps were accepted, it's vulnerable
        boolean isVulnerable = successCount > 1;

        return new ReplayTestResult(
            isVulnerable,
            "Messages with same ID but different timestamps",
            successCount,
            REPLAY_COUNT,
            responses
        );
    }

    /**
     * Test replay without message ID (no deduplication).
     */
    private ReplayTestResult testReplayWithoutMessageId(
            ProtocolClient client,
            AsyncOperationSpec operation,
            ScanContext context) throws ProtocolException {

        String channel = operation.getChannelName();
        String timestamp = java.time.Instant.now().toString();

        // Message without ID field
        String testMessage = String.format(
            "{\"timestamp\":\"%s\",\"action\":\"test\",\"data\":\"same-content\"}",
            timestamp
        );

        int successCount = 0;
        List<String> responses = new ArrayList<>();

        // Send the same message (without ID) multiple times
        for (int i = 0; i < REPLAY_COUNT; i++) {
            incrementRequestCount();
            applyDelay(context);

            try {
                ProtocolRequest request = ProtocolRequest.builder()
                        .type(ProtocolRequest.RequestType.PUBLISH)
                        .channel(channel)
                        .payload(testMessage)
                        .timeoutMs(5000)
                        .build();

                ProtocolResponse response = client.send(request);

                if (response.isSuccess()) {
                    successCount++;
                    responses.add("Attempt " + (i + 1) + ": Success");
                }

            } catch (ProtocolException e) {
                responses.add("Attempt " + (i + 1) + ": " + e.getMessage());
            }
        }

        // If all messages were accepted, no deduplication exists
        boolean isVulnerable = successCount >= REPLAY_COUNT;

        return new ReplayTestResult(
            isVulnerable,
            testMessage,
            successCount,
            REPLAY_COUNT,
            responses
        );
    }

    /**
     * Get severity based on channel name and replay type.
     */
    private Severity getSeverityForReplay(AsyncOperationSpec operation, String replayType) {
        String channelName = operation.getChannelName().toLowerCase();

        // Critical for financial or command channels
        if (channelName.contains("payment") ||
            channelName.contains("transaction") ||
            channelName.contains("order") ||
            channelName.contains("command") ||
            channelName.contains("transfer")) {
            return Severity.CRITICAL;
        }

        // High for user actions
        if (channelName.contains("action") ||
            channelName.contains("event") ||
            channelName.contains("update")) {
            return Severity.HIGH;
        }

        return Severity.MEDIUM;
    }

    /**
     * Create vulnerability report for replay attack.
     */
    private AsyncVulnerabilityReport createVulnerabilityReport(
            AsyncOperationSpec operation,
            ProtocolClient client,
            String replayType,
            ReplayTestResult result) {

        String channelName = operation.getChannelName();
        Severity severity = getSeverityForReplay(operation, replayType);

        String title = getLocalizedMessage("vuln.replay.title",
                channelName, getLocalizedMessage("replay_type." + replayType));

        String description = getLocalizedMessage("vuln.replay.description",
                channelName, result.successfulReplays, result.totalAttempts,
                getLocalizedMessage("replay_type." + replayType));

        String reproductionSteps =
                "1. " + getLocalizedMessage("vuln.replay.repro.step1", channelName) + "\n" +
                "2. " + getLocalizedMessage("vuln.replay.repro.step2") + "\n" +
                "3. " + getLocalizedMessage("vuln.replay.repro.step3", result.successfulReplays) + "\n" +
                "4. " + getLocalizedMessage("vuln.replay.repro.step4");

        AsyncVulnerabilityReport.ProtocolMetadata protocolMetadata =
                AsyncVulnerabilityReport.ProtocolMetadata.builder()
                        .protocol(client.getProtocol())
                        .protocolVersion(client.getProtocolVersion())
                        .channel(channelName)
                        .build();

        AsyncVulnerabilityReport.Builder builder = AsyncVulnerabilityReport.builder()
                .type(AsyncVulnerabilityReport.AsyncVulnerabilityType.MESSAGE_REPLAY)
                .severity(severity)
                .operation(operation)
                .protocolMetadata(protocolMetadata)
                .title(title)
                .description(description)
                .reproductionSteps(reproductionSteps)
                .addEvidence("channel", channelName)
                .addEvidence("replayType", replayType)
                .addEvidence("successfulReplays", result.successfulReplays)
                .addEvidence("totalAttempts", result.totalAttempts)
                .addEvidence("testPayload", result.payload)
                .addEvidence("responses", result.responses);

        // Add recommendations
        for (int i = 1; i <= 5; i++) {
            builder.addRecommendation(getLocalizedMessage("vuln.recommendation" + i));
        }

        return builder.build();
    }

    /**
     * Result of replay attack test.
     */
    private static class ReplayTestResult {
        final boolean isVulnerable;
        final String payload;
        final int successfulReplays;
        final int totalAttempts;
        final List<String> responses;

        ReplayTestResult(boolean isVulnerable, String payload,
                        int successfulReplays, int totalAttempts,
                        List<String> responses) {
            this.isVulnerable = isVulnerable;
            this.payload = payload;
            this.successfulReplays = successfulReplays;
            this.totalAttempts = totalAttempts;
            this.responses = responses;
        }
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
