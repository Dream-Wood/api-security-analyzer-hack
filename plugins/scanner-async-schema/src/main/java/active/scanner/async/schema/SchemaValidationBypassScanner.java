package active.scanner.async.schema;

import active.async.*;
import active.protocol.*;
import active.scanner.ScanContext;
import model.AsyncOperationSpec;
import model.AsyncOperationType;
import model.Severity;

import java.util.*;

/**
 * Scanner that detects schema validation bypass vulnerabilities in AsyncAPI.
 *
 * <p>This scanner tests if message consumers properly validate message schemas by:
 * <ul>
 *   <li>Sending messages with missing required fields</li>
 *   <li>Sending messages with invalid data types</li>
 *   <li>Sending messages with extra unexpected fields</li>
 *   <li>Sending malformed JSON/XML payloads</li>
 *   <li>Sending extremely large payloads</li>
 * </ul>
 *
 * <p><b>Test Strategy:</b>
 * <ol>
 *   <li>Identify message schema from AsyncAPI specification</li>
 *   <li>Generate invalid payloads that violate schema constraints</li>
 *   <li>Attempt to publish invalid messages</li>
 *   <li>Report vulnerability if invalid messages are accepted</li>
 * </ol>
 *
 * <p><b>Supported Protocols:</b> All async protocols
 */
public class SchemaValidationBypassScanner extends AbstractAsyncScanner {

    private static final String SCANNER_NAME = "Schema Validation Bypass Scanner";
    private static final String VERSION = "1.0.0";
    private static final String AUTHOR = "API Security Analyzer Team";

    // Test cases for schema validation bypass
    private enum ValidationTest {
        MISSING_REQUIRED_FIELD,
        INVALID_DATA_TYPE,
        EXTRA_FIELDS,
        MALFORMED_JSON,
        EMPTY_PAYLOAD,
        NULL_VALUES,
        EXTREMELY_LARGE_PAYLOAD,
        NEGATIVE_VALUES,
        BOUNDARY_VALUES
    }

    /**
     * Get localized message from scanner bundle.
     */
    private String getLocalizedMessage(String key, Object... params) {
        try {
            String message = com.apisecurity.analyzer.core.i18n.PluginMessageService.getMessage(
                "asyncschema",
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

    public SchemaValidationBypassScanner() {
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
        // Applicable to PUBLISH operations (to test schema validation)
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

        // Test each validation scenario
        for (ValidationTest test : ValidationTest.values()) {
            if (shouldStopScan(context)) {
                break;
            }

            try {
                ValidationResult result = testValidationBypass(
                        client, operation, test, context);

                if (result.isBypassed) {
                    AsyncVulnerabilityReport vulnerability = createVulnerabilityReport(
                            operation, client, test, result);

                    resultBuilder.addVulnerability(vulnerability);

                    info(getLocalizedMessage("log.found_vulnerability",
                            test.name(), operation.getChannelName()));
                }

            } catch (ProtocolException e) {
                if (e.getErrorType() == ProtocolException.ErrorType.AUTHENTICATION_FAILED) {
                    debug(getLocalizedMessage("log.auth_required",
                            operation.getChannelName()));
                    break;
                }
                // Some errors are expected (e.g., validation errors), continue testing
                debug("Expected error for test " + test.name() + ": " + e.getMessage());
            }
        }

        long duration = System.currentTimeMillis() - startTime;
        return resultBuilder
                .success(true)
                .durationMs(duration)
                .build();
    }

    /**
     * Test a specific schema validation bypass scenario.
     */
    private ValidationResult testValidationBypass(
            ProtocolClient client,
            AsyncOperationSpec operation,
            ValidationTest test,
            ScanContext context) throws ProtocolException {

        incrementRequestCount();
        applyDelay(context);

        String channel = operation.getChannelName();
        String invalidPayload = generateInvalidPayload(test);

        try {
            ProtocolRequest request = ProtocolRequest.builder()
                    .type(ProtocolRequest.RequestType.PUBLISH)
                    .channel(channel)
                    .payload(invalidPayload)
                    .timeoutMs(5000)
                    .build();

            ProtocolResponse response = client.send(request);

            // If message was accepted despite being invalid, validation is bypassed
            if (response.isSuccess()) {
                return new ValidationResult(true, test, invalidPayload,
                        "Invalid message was accepted");
            }

            return new ValidationResult(false, test, invalidPayload,
                    "Message properly rejected");

        } catch (ProtocolException e) {
            // Check if error indicates validation (good) or other issue (might be bad)
            if (isValidationError(e.getMessage())) {
                return new ValidationResult(false, test, invalidPayload,
                        "Properly validated: " + e.getMessage());
            }
            throw e;
        }
    }

    /**
     * Generate invalid payload for specific validation test.
     */
    private String generateInvalidPayload(ValidationTest test) {
        switch (test) {
            case MISSING_REQUIRED_FIELD:
                return "{\"scanner\":\"test\"}";

            case INVALID_DATA_TYPE:
                return "{\"userId\":\"not-a-number\",\"amount\":\"invalid\",\"active\":\"not-boolean\"}";

            case EXTRA_FIELDS:
                return "{\"userId\":123,\"__proto__\":{\"isAdmin\":true},\"constructor\":{\"prototype\":{\"isAdmin\":true}}}";

            case MALFORMED_JSON:
                return "{\"userId\":123,\"data\":\"unclosed";

            case EMPTY_PAYLOAD:
                return "";

            case NULL_VALUES:
                return "{\"userId\":null,\"email\":null,\"data\":null}";

            case EXTREMELY_LARGE_PAYLOAD:
                StringBuilder large = new StringBuilder("{\"data\":\"");
                for (int i = 0; i < 10000; i++) {
                    large.append("A");
                }
                large.append("\"}");
                return large.toString();

            case NEGATIVE_VALUES:
                return "{\"userId\":-1,\"amount\":-999999,\"count\":-1}";

            case BOUNDARY_VALUES:
                return "{\"userId\":2147483647,\"amount\":9999999999999.99,\"count\":0}";

            default:
                return "{\"test\":true}";
        }
    }

    /**
     * Check if error message indicates validation (good security practice).
     */
    private boolean isValidationError(String errorMsg) {
        if (errorMsg == null) {
            return false;
        }

        String lower = errorMsg.toLowerCase();
        return lower.contains("validation") ||
               lower.contains("invalid") ||
               lower.contains("schema") ||
               lower.contains("required field") ||
               lower.contains("type mismatch") ||
               lower.contains("malformed");
    }

    /**
     * Get severity for validation bypass type.
     */
    private Severity getSeverityForTest(ValidationTest test) {
        switch (test) {
            case EXTRA_FIELDS:
            case MALFORMED_JSON:
                return Severity.HIGH;

            case MISSING_REQUIRED_FIELD:
            case INVALID_DATA_TYPE:
            case EXTREMELY_LARGE_PAYLOAD:
                return Severity.MEDIUM;

            default:
                return Severity.LOW;
        }
    }

    /**
     * Create vulnerability report for schema validation bypass.
     */
    private AsyncVulnerabilityReport createVulnerabilityReport(
            AsyncOperationSpec operation,
            ProtocolClient client,
            ValidationTest test,
            ValidationResult result) {

        String channelName = operation.getChannelName();
        Severity severity = getSeverityForTest(test);

        String title = getLocalizedMessage("vuln.schema_bypass.title",
                channelName, getLocalizedMessage("test_type." + test.name()));

        String description = getLocalizedMessage("vuln.schema_bypass.description",
                channelName, getLocalizedMessage("test_type." + test.name()));

        String reproductionSteps =
                "1. " + getLocalizedMessage("vuln.schema_bypass.repro.step1", channelName) + "\n" +
                "2. " + getLocalizedMessage("vuln.schema_bypass.repro.step2") + "\n" +
                "3. " + getLocalizedMessage("vuln.schema_bypass.repro.step3") + "\n" +
                "4. " + getLocalizedMessage("vuln.schema_bypass.repro.step4");

        AsyncVulnerabilityReport.ProtocolMetadata protocolMetadata =
                AsyncVulnerabilityReport.ProtocolMetadata.builder()
                        .protocol(client.getProtocol())
                        .protocolVersion(client.getProtocolVersion())
                        .channel(channelName)
                        .build();

        AsyncVulnerabilityReport.Builder builder = AsyncVulnerabilityReport.builder()
                .type(AsyncVulnerabilityReport.AsyncVulnerabilityType.SCHEMA_VALIDATION_BYPASS)
                .severity(severity)
                .operation(operation)
                .protocolMetadata(protocolMetadata)
                .title(title)
                .description(description)
                .reproductionSteps(reproductionSteps)
                .addEvidence("channel", channelName)
                .addEvidence("validationTest", test.name())
                .addEvidence("invalidPayload", result.payload)
                .addEvidence("result", result.message);

        // Add recommendations
        for (int i = 1; i <= 5; i++) {
            builder.addRecommendation(getLocalizedMessage("vuln.recommendation" + i));
        }

        return builder.build();
    }

    /**
     * Result of validation bypass test.
     */
    private static class ValidationResult {
        final boolean isBypassed;
        final ValidationTest test;
        final String payload;
        final String message;

        ValidationResult(boolean isBypassed, ValidationTest test, String payload, String message) {
            this.isBypassed = isBypassed;
            this.test = test;
            this.payload = payload;
            this.message = message;
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
