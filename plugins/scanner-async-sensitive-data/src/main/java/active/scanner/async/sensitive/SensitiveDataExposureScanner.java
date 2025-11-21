package active.scanner.async.sensitive;

import active.async.*;
import active.protocol.*;
import active.scanner.ScanContext;
import model.AsyncOperationSpec;
import model.AsyncOperationType;
import model.Severity;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scanner that detects sensitive data exposure in AsyncAPI message payloads.
 *
 * <p>This scanner subscribes to channels and analyzes message content for:
 * <ul>
 *   <li>Personally Identifiable Information (PII)</li>
 *   <li>Credit card numbers</li>
 *   <li>Social security numbers</li>
 *   <li>Email addresses and phone numbers</li>
 *   <li>API keys and tokens</li>
 *   <li>Passwords and secrets</li>
 * </ul>
 *
 * <p><b>Test Strategy:</b>
 * <ol>
 *   <li>Subscribe to channel and capture sample messages</li>
 *   <li>Analyze message payloads using regex patterns</li>
 *   <li>Report findings with severity based on data type</li>
 * </ol>
 *
 * <p><b>Supported Protocols:</b> All async protocols
 */
public class SensitiveDataExposureScanner extends AbstractAsyncScanner {

    private static final String SCANNER_NAME = "Sensitive Data Exposure Scanner";
    private static final String VERSION = "1.0.0";
    private static final String AUTHOR = "API Security Analyzer Team";

    // Regex patterns for sensitive data detection
    private static final Map<String, Pattern> SENSITIVE_PATTERNS = new HashMap<>();

    static {
        // Credit card numbers (Visa, MasterCard, Amex, Discover)
        SENSITIVE_PATTERNS.put("credit_card",
            Pattern.compile("\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b"));

        // Social Security Numbers (US)
        SENSITIVE_PATTERNS.put("ssn",
            Pattern.compile("\\b(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b"));

        // Email addresses
        SENSITIVE_PATTERNS.put("email",
            Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"));

        // Phone numbers (international format)
        SENSITIVE_PATTERNS.put("phone",
            Pattern.compile("\\b(?:\\+?\\d{1,3}[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b"));

        // API keys and tokens (generic patterns)
        SENSITIVE_PATTERNS.put("api_key",
            Pattern.compile("(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)[\"']?\\s*[:=]\\s*[\"']?([a-zA-Z0-9_\\-]{20,})"));

        // JWT tokens
        SENSITIVE_PATTERNS.put("jwt",
            Pattern.compile("eyJ[A-Za-z0-9_-]*\\.eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*"));

        // AWS Access Keys
        SENSITIVE_PATTERNS.put("aws_key",
            Pattern.compile("(?i)(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}"));

        // Generic passwords in JSON/XML
        SENSITIVE_PATTERNS.put("password",
            Pattern.compile("(?i)(password|passwd|pwd)[\"']?\\s*[:=]\\s*[\"']?([^\\s\"']{4,})"));

        // IPv4 addresses (private ranges - might be sensitive)
        SENSITIVE_PATTERNS.put("private_ip",
            Pattern.compile("\\b(?:10\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])|192\\.168)\\.\\d{1,3}\\.\\d{1,3}\\b"));
    }

    /**
     * Get localized message from scanner bundle.
     */
    private String getLocalizedMessage(String key, Object... params) {
        try {
            String message = com.apisecurity.analyzer.core.i18n.PluginMessageService.getMessage(
                "asyncsensitive",
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

    public SensitiveDataExposureScanner() {
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
        // Applicable to SUBSCRIBE operations (to receive messages)
        return operation.getOperationType() == AsyncOperationType.SUBSCRIBE;
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
            // Subscribe and capture sample messages
            List<String> messages = captureSampleMessages(client, operation, context);

            if (messages.isEmpty()) {
                debug(getLocalizedMessage("log.no_messages",
                        operation.getChannelName()));
                long duration = System.currentTimeMillis() - startTime;
                return resultBuilder
                        .success(true)
                        .durationMs(duration)
                        .build();
            }

            // Analyze messages for sensitive data
            Map<String, List<String>> findings = analyzeSensitiveData(messages);

            // Create vulnerability reports for findings
            for (Map.Entry<String, List<String>> entry : findings.entrySet()) {
                String dataType = entry.getKey();
                List<String> matches = entry.getValue();

                AsyncVulnerabilityReport vulnerability = createVulnerabilityReport(
                        operation, client, dataType, matches);

                resultBuilder.addVulnerability(vulnerability);

                info(getLocalizedMessage("log.found_vulnerability",
                        dataType, operation.getChannelName(), matches.size()));
            }

            long duration = System.currentTimeMillis() - startTime;
            return resultBuilder
                    .success(true)
                    .durationMs(duration)
                    .build();

        } catch (ProtocolException e) {
            throw e;
        }
    }

    /**
     * Capture sample messages from the channel.
     */
    private List<String> captureSampleMessages(
            ProtocolClient client,
            AsyncOperationSpec operation,
            ScanContext context) throws ProtocolException {

        incrementRequestCount();
        applyDelay(context);

        String channel = operation.getChannelName();
        List<String> messages = new ArrayList<>();

        try {
            // Subscribe to channel with timeout
            ProtocolRequest request = ProtocolRequest.builder()
                    .type(ProtocolRequest.RequestType.SUBSCRIBE)
                    .channel(channel)
                    .timeoutMs(10000) // 10 second timeout to collect messages
                    .build();

            ProtocolResponse response = client.send(request);

            // Extract messages from response
            if (response.isSuccess()) {
                for (ProtocolMessage message : response.getMessages()) {
                    if (message.getPayload() != null && !message.getPayload().isEmpty()) {
                        messages.add(message.getPayload());
                    }
                }
            }

            // In a real implementation, we might collect multiple messages
            // over a period of time using async message handlers

        } catch (ProtocolException e) {
            if (e.getErrorType() == ProtocolException.ErrorType.AUTHENTICATION_FAILED) {
                debug(getLocalizedMessage("log.auth_required", channel));
                return messages; // Return empty list
            }
            throw e;
        }

        return messages;
    }

    /**
     * Analyze messages for sensitive data patterns.
     */
    private Map<String, List<String>> analyzeSensitiveData(List<String> messages) {
        Map<String, List<String>> findings = new HashMap<>();

        for (String message : messages) {
            if (message == null || message.isEmpty()) {
                continue;
            }

            // Check each pattern
            for (Map.Entry<String, Pattern> entry : SENSITIVE_PATTERNS.entrySet()) {
                String dataType = entry.getKey();
                Pattern pattern = entry.getValue();

                Matcher matcher = pattern.matcher(message);
                while (matcher.find()) {
                    String match = matcher.group();

                    // Mask the sensitive data in findings
                    String maskedMatch = maskSensitiveData(match, dataType);

                    findings.computeIfAbsent(dataType, k -> new ArrayList<>())
                            .add(maskedMatch);
                }
            }
        }

        return findings;
    }

    /**
     * Mask sensitive data for reporting (show only partial info).
     */
    private String maskSensitiveData(String data, String dataType) {
        if (data.length() <= 4) {
            return "***";
        }

        switch (dataType) {
            case "credit_card":
                return "****-****-****-" + data.substring(data.length() - 4);
            case "ssn":
                return "***-**-" + data.substring(data.length() - 4);
            case "email":
                int atIndex = data.indexOf('@');
                if (atIndex > 2) {
                    return data.substring(0, 2) + "***@" + data.substring(atIndex + 1);
                }
                return "***@***";
            case "phone":
                return "***-***-" + data.substring(Math.max(0, data.length() - 4));
            default:
                return data.substring(0, Math.min(4, data.length())) + "***";
        }
    }

    /**
     * Get severity based on data type.
     */
    private Severity getSeverityForDataType(String dataType) {
        switch (dataType) {
            case "credit_card":
            case "ssn":
            case "password":
            case "api_key":
            case "aws_key":
                return Severity.CRITICAL;
            case "jwt":
            case "private_ip":
                return Severity.HIGH;
            case "email":
            case "phone":
                return Severity.MEDIUM;
            default:
                return Severity.LOW;
        }
    }

    /**
     * Create vulnerability report for sensitive data exposure.
     */
    private AsyncVulnerabilityReport createVulnerabilityReport(
            AsyncOperationSpec operation,
            ProtocolClient client,
            String dataType,
            List<String> matches) {

        String channelName = operation.getChannelName();
        Severity severity = getSeverityForDataType(dataType);

        String title = getLocalizedMessage("vuln.sensitive_data.title",
                getLocalizedMessage("datatype." + dataType), channelName);

        String description = getLocalizedMessage("vuln.sensitive_data.description",
                channelName, getLocalizedMessage("datatype." + dataType), matches.size());

        String reproductionSteps =
                "1. " + getLocalizedMessage("vuln.sensitive_data.repro.step1", channelName) + "\n" +
                "2. " + getLocalizedMessage("vuln.sensitive_data.repro.step2") + "\n" +
                "3. " + getLocalizedMessage("vuln.sensitive_data.repro.step3",
                        getLocalizedMessage("datatype." + dataType)) + "\n" +
                "4. " + getLocalizedMessage("vuln.sensitive_data.repro.step4");

        AsyncVulnerabilityReport.ProtocolMetadata protocolMetadata =
                AsyncVulnerabilityReport.ProtocolMetadata.builder()
                        .protocol(client.getProtocol())
                        .protocolVersion(client.getProtocolVersion())
                        .channel(channelName)
                        .build();

        AsyncVulnerabilityReport.Builder builder = AsyncVulnerabilityReport.builder()
                .type(AsyncVulnerabilityReport.AsyncVulnerabilityType.SENSITIVE_DATA_EXPOSURE)
                .severity(severity)
                .operation(operation)
                .protocolMetadata(protocolMetadata)
                .title(title)
                .description(description)
                .reproductionSteps(reproductionSteps)
                .addEvidence("channel", channelName)
                .addEvidence("dataType", dataType)
                .addEvidence("matchCount", matches.size())
                .addEvidence("samples", matches.subList(0, Math.min(3, matches.size())));

        // Add recommendations
        for (int i = 1; i <= 5; i++) {
            builder.addRecommendation(getLocalizedMessage("vuln.recommendation" + i));
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
