package active.scanner.async.injection;

import active.async.*;
import active.protocol.*;
import active.scanner.ScanContext;
import model.AsyncOperationSpec;
import model.AsyncOperationType;
import model.Severity;

import java.util.*;

/**
 * Scanner that detects message injection vulnerabilities in AsyncAPI operations.
 *
 * <p>This scanner tests for injection vulnerabilities by sending payloads with:
 * <ul>
 *   <li>SQL injection attempts</li>
 *   <li>NoSQL injection attempts</li>
 *   <li>Command injection attempts</li>
 *   <li>LDAP injection attempts</li>
 *   <li>XSS payloads (for messages displayed in UI)</li>
 *   <li>XML/JSON injection attempts</li>
 * </ul>
 *
 * <p><b>Test Strategy:</b>
 * <ol>
 *   <li>Identify PUBLISH operations that accept user-controlled data</li>
 *   <li>Send messages with injection payloads</li>
 *   <li>Monitor for error responses or behavioral changes</li>
 *   <li>Report vulnerabilities if injection is successful</li>
 * </ol>
 *
 * <p><b>Supported Protocols:</b> All async protocols
 */
public class MessageInjectionScanner extends AbstractAsyncScanner {

    private static final String SCANNER_NAME = "Message Injection Scanner";
    private static final String VERSION = "1.0.0";
    private static final String AUTHOR = "API Security Analyzer Team";

    // Injection payloads for different attack types
    private static final Map<String, List<String>> INJECTION_PAYLOADS = new HashMap<>();

    static {
        // SQL Injection payloads
        INJECTION_PAYLOADS.put("sql", Arrays.asList(
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "admin'--",
            "' UNION SELECT NULL--",
            "1'; DROP TABLE users--"
        ));

        // NoSQL Injection payloads (MongoDB)
        INJECTION_PAYLOADS.put("nosql", Arrays.asList(
            "{\"$ne\": null}",
            "{\"$gt\": \"\"}",
            "{\"$where\": \"1==1\"}",
            "[$ne]=1"
        ));

        // Command Injection payloads
        INJECTION_PAYLOADS.put("command", Arrays.asList(
            "; ls -la",
            "| whoami",
            "`id`",
            "$(cat /etc/passwd)",
            "&& echo vulnerable"
        ));

        // LDAP Injection payloads
        INJECTION_PAYLOADS.put("ldap", Arrays.asList(
            "*",
            "*)(&",
            "*)(uid=*))(|(uid=*",
            "admin)(&(password=*)"
        ));

        // XSS payloads (for messages displayed in UI)
        INJECTION_PAYLOADS.put("xss", Arrays.asList(
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ));

        // XML Injection payloads
        INJECTION_PAYLOADS.put("xml", Arrays.asList(
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
            "</tag><injected>malicious</injected><tag>",
            "<!--<script>alert('XSS')</script>-->"
        ));
    }

    /**
     * Get localized message from scanner bundle.
     */
    private String getLocalizedMessage(String key, Object... params) {
        try {
            String message = com.apisecurity.analyzer.core.i18n.PluginMessageService.getMessage(
                "asyncinjection",
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

    public MessageInjectionScanner() {
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
        // Applicable to PUBLISH operations (to send injection payloads)
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

        // Test different injection types
        for (Map.Entry<String, List<String>> entry : INJECTION_PAYLOADS.entrySet()) {
            if (shouldStopScan(context)) {
                break;
            }

            String injectionType = entry.getKey();
            List<String> payloads = entry.getValue();

            for (String payload : payloads) {
                if (shouldStopScan(context)) {
                    break;
                }

                try {
                    InjectionResult result = testInjectionPayload(
                            client, operation, injectionType, payload, context);

                    if (result.isVulnerable) {
                        AsyncVulnerabilityReport vulnerability = createVulnerabilityReport(
                                operation, client, injectionType, payload, result);

                        resultBuilder.addVulnerability(vulnerability);

                        info(getLocalizedMessage("log.found_vulnerability",
                                injectionType, operation.getChannelName()));

                        // Stop testing this injection type if we found a vulnerability
                        break;
                    }

                } catch (ProtocolException e) {
                    if (e.getErrorType() == ProtocolException.ErrorType.AUTHENTICATION_FAILED) {
                        debug(getLocalizedMessage("log.auth_required",
                                operation.getChannelName()));
                        break;
                    }
                    // Log but continue with other payloads
                    debug("Error testing payload: " + e.getMessage());
                }
            }
        }

        long duration = System.currentTimeMillis() - startTime;
        return resultBuilder
                .success(true)
                .durationMs(duration)
                .build();
    }

    /**
     * Test a single injection payload.
     */
    private InjectionResult testInjectionPayload(
            ProtocolClient client,
            AsyncOperationSpec operation,
            String injectionType,
            String payload,
            ScanContext context) throws ProtocolException {

        incrementRequestCount();
        applyDelay(context);

        String channel = operation.getChannelName();

        // Create message with injection payload
        String testMessage = createInjectionMessage(payload, injectionType);

        try {
            ProtocolRequest request = ProtocolRequest.builder()
                    .type(ProtocolRequest.RequestType.PUBLISH)
                    .channel(channel)
                    .payload(testMessage)
                    .timeoutMs(5000)
                    .build();

            ProtocolResponse response = client.send(request);

            // Analyze response for injection indicators
            return analyzeResponse(response, injectionType, payload);

        } catch (ProtocolException e) {
            // Check if error message indicates successful injection
            if (isInjectionErrorIndicator(e.getMessage(), injectionType)) {
                return new InjectionResult(true, e.getMessage());
            }
            throw e;
        }
    }

    /**
     * Create test message with injection payload.
     */
    private String createInjectionMessage(String payload, String injectionType) {
        // Create a JSON message with the payload in different fields
        return String.format(
            "{\"test\":true,\"scanner\":\"api-security-analyzer\",\"data\":\"%s\",\"id\":\"%s\",\"type\":\"%s\"}",
            escapeJson(payload), escapeJson(payload), injectionType
        );
    }

    /**
     * Escape JSON special characters (basic escaping).
     */
    private String escapeJson(String str) {
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }

    /**
     * Analyze response for injection indicators.
     */
    private InjectionResult analyzeResponse(ProtocolResponse response,
                                           String injectionType,
                                           String payload) {

        if (!response.isSuccess()) {
            String errorMsg = response.getStatusMessage();
            if (isInjectionErrorIndicator(errorMsg, injectionType)) {
                return new InjectionResult(true, errorMsg);
            }
        }

        // Check response messages for injection indicators
        for (ProtocolMessage message : response.getMessages()) {
            String responsePayload = message.getPayload();
            if (responsePayload != null && containsInjectionIndicators(responsePayload, injectionType)) {
                return new InjectionResult(true, "Injection detected in response");
            }
        }

        return new InjectionResult(false, null);
    }

    /**
     * Check if error message indicates successful injection.
     */
    private boolean isInjectionErrorIndicator(String errorMsg, String injectionType) {
        if (errorMsg == null) {
            return false;
        }

        String lowerError = errorMsg.toLowerCase();

        switch (injectionType) {
            case "sql":
                return lowerError.contains("sql") ||
                       lowerError.contains("syntax error") ||
                       lowerError.contains("mysql") ||
                       lowerError.contains("postgresql") ||
                       lowerError.contains("ora-");

            case "nosql":
                return lowerError.contains("mongodb") ||
                       lowerError.contains("$where") ||
                       lowerError.contains("bson");

            case "command":
                return lowerError.contains("sh:") ||
                       lowerError.contains("command not found") ||
                       lowerError.contains("/bin/");

            case "ldap":
                return lowerError.contains("ldap") ||
                       lowerError.contains("invalid dn");

            case "xml":
                return lowerError.contains("xml") ||
                       lowerError.contains("entity") ||
                       lowerError.contains("dtd");

            default:
                return false;
        }
    }

    /**
     * Check if response contains injection indicators.
     */
    private boolean containsInjectionIndicators(String response, String injectionType) {
        String lowerResponse = response.toLowerCase();

        switch (injectionType) {
            case "sql":
                return lowerResponse.contains("root@") ||
                       lowerResponse.contains("admin") ||
                       lowerResponse.contains("database");

            case "command":
                return lowerResponse.contains("uid=") ||
                       lowerResponse.contains("root:") ||
                       lowerResponse.contains("/bin/bash");

            default:
                return false;
        }
    }

    /**
     * Get severity based on injection type.
     */
    private Severity getSeverityForInjection(String injectionType) {
        switch (injectionType) {
            case "sql":
            case "nosql":
            case "command":
                return Severity.CRITICAL;
            case "ldap":
            case "xml":
                return Severity.HIGH;
            case "xss":
                return Severity.MEDIUM;
            default:
                return Severity.MEDIUM;
        }
    }

    /**
     * Create vulnerability report for injection finding.
     */
    private AsyncVulnerabilityReport createVulnerabilityReport(
            AsyncOperationSpec operation,
            ProtocolClient client,
            String injectionType,
            String payload,
            InjectionResult result) {

        String channelName = operation.getChannelName();
        Severity severity = getSeverityForInjection(injectionType);

        String title = getLocalizedMessage("vuln.injection.title",
                getLocalizedMessage("injection_type." + injectionType), channelName);

        String description = getLocalizedMessage("vuln.injection.description",
                channelName, getLocalizedMessage("injection_type." + injectionType));

        String reproductionSteps =
                "1. " + getLocalizedMessage("vuln.injection.repro.step1", channelName) + "\n" +
                "2. " + getLocalizedMessage("vuln.injection.repro.step2", payload) + "\n" +
                "3. " + getLocalizedMessage("vuln.injection.repro.step3") + "\n" +
                "4. " + getLocalizedMessage("vuln.injection.repro.step4");

        AsyncVulnerabilityReport.ProtocolMetadata protocolMetadata =
                AsyncVulnerabilityReport.ProtocolMetadata.builder()
                        .protocol(client.getProtocol())
                        .protocolVersion(client.getProtocolVersion())
                        .channel(channelName)
                        .build();

        AsyncVulnerabilityReport.Builder builder = AsyncVulnerabilityReport.builder()
                .type(AsyncVulnerabilityReport.AsyncVulnerabilityType.MESSAGE_INJECTION)
                .severity(severity)
                .operation(operation)
                .protocolMetadata(protocolMetadata)
                .title(title)
                .description(description)
                .reproductionSteps(reproductionSteps)
                .addEvidence("channel", channelName)
                .addEvidence("injectionType", injectionType)
                .addEvidence("payload", payload)
                .addEvidence("indicator", result.indicator);

        // Add recommendations
        for (int i = 1; i <= 5; i++) {
            builder.addRecommendation(getLocalizedMessage("vuln.recommendation" + i));
        }

        return builder.build();
    }

    /**
     * Result of injection test.
     */
    private static class InjectionResult {
        final boolean isVulnerable;
        final String indicator;

        InjectionResult(boolean isVulnerable, String indicator) {
            this.isVulnerable = isVulnerable;
            this.indicator = indicator;
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
