package active.scanner.injection;

import active.http.HttpClient;
import active.model.ApiEndpoint;
import active.model.TestRequest;
import active.model.TestResponse;
import active.model.VulnerabilityReport;
import active.scanner.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import model.ParameterSpec;
import model.Severity;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Scanner for detecting OS Command Injection vulnerabilities.
 *
 * <p>Command injection occurs when an application passes unsafe user input to a system shell.
 * This scanner tests for:
 * <ul>
 *   <li>Error-based command injection (shell error messages in responses)</li>
 *   <li>Time-based blind command injection (delays using sleep commands)</li>
 *   <li>Output-based command injection (command output in response)</li>
 * </ul>
 */
public final class CommandInjectionScanner extends AbstractScanner {

    private static final String SCANNER_ID = "command-injection-scanner";
    private static final String SCANNER_NAME = "Command Injection Scanner";
    private static final String SCANNER_DESCRIPTION =
        "Detects OS Command Injection vulnerabilities in API parameters";

    // Command injection patterns for detection
    private static final List<Pattern> COMMAND_ERROR_PATTERNS = List.of(
        // Unix/Linux shell errors
        Pattern.compile("sh: .*: command not found", Pattern.CASE_INSENSITIVE),
        Pattern.compile("bash: .*: command not found", Pattern.CASE_INSENSITIVE),
        Pattern.compile("/bin/(bash|sh):", Pattern.CASE_INSENSITIVE),
        Pattern.compile("syntax error near unexpected token", Pattern.CASE_INSENSITIVE),

        // Windows command errors
        Pattern.compile("'.*' is not recognized as an internal or external command", Pattern.CASE_INSENSITIVE),
        Pattern.compile("The system cannot find the path specified", Pattern.CASE_INSENSITIVE),
        Pattern.compile("cmd.exe", Pattern.CASE_INSENSITIVE),

        // Common system file indicators
        Pattern.compile("/etc/passwd", Pattern.CASE_INSENSITIVE),
        Pattern.compile("root:.*:0:0:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("C:\\\\Windows\\\\System32", Pattern.CASE_INSENSITIVE)
    );

    // Command injection payloads for error-based detection
    private static final List<String> ERROR_BASED_PAYLOADS = List.of(
        // Command separators
        "; ls",
        "| ls",
        "& dir",
        "&& dir",
        "`ls`",
        "$(ls)",

        // Path traversal with commands
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; type C:\\Windows\\System32\\drivers\\etc\\hosts",

        // Command injection with special chars
        "; id;",
        "| whoami",
        "& whoami",
        "`whoami`",
        "$(whoami)",

        // Newline-based injection (only for body/header injection, not URL parameters)
        "\nls\n",
        "\nid\n",
        "\nwhoami\n"
    );

    /**
     * Filter payloads to exclude those with illegal characters for URL/path usage.
     * Newlines and other control characters are not allowed in URLs.
     */
    private static List<String> filterPayloadsForUrl(List<String> payloads) {
        return payloads.stream()
            .filter(payload -> !payload.contains("\n") && !payload.contains("\r") && !payload.contains("\t"))
            .toList();
    }

    // Time-based payloads (should cause ~5 second delay)
    private static final List<String> TIME_BASED_PAYLOADS = List.of(
        // Unix/Linux
        "; sleep 5",
        "| sleep 5",
        "& sleep 5",
        "&& sleep 5",
        "`sleep 5`",
        "$(sleep 5)",

        // Windows
        "& ping -n 6 127.0.0.1",
        "| ping -n 6 127.0.0.1",
        "&& timeout /t 5"
    );

    // Payloads that should produce identifiable output
    private static final List<OutputPayloadPair> OUTPUT_BASED_PAYLOADS = List.of(
        new OutputPayloadPair("; echo 'CMDTEST123'", "CMDTEST123"),
        new OutputPayloadPair("| echo 'CMDTEST123'", "CMDTEST123"),
        new OutputPayloadPair("&& echo CMDTEST123", "CMDTEST123"),
        new OutputPayloadPair("`echo CMDTEST123`", "CMDTEST123"),
        new OutputPayloadPair("$(echo CMDTEST123)", "CMDTEST123")
    );

    private final ObjectMapper objectMapper = new ObjectMapper();

    public CommandInjectionScanner() {
        super();
    }

    public CommandInjectionScanner(ScannerConfig config) {
        super(config);
    }

    @Override
    public String getId() {
        return SCANNER_ID;
    }

    @Override
    public String getName() {
        return SCANNER_NAME;
    }

    @Override
    public String getDescription() {
        return SCANNER_DESCRIPTION;
    }

    @Override
    public List<VulnerabilityReport.VulnerabilityType> getDetectedVulnerabilities() {
        return List.of(VulnerabilityReport.VulnerabilityType.COMMAND_INJECTION);
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // Command injection can occur in any endpoint that processes parameters
        return !endpoint.getQueryParameters().isEmpty() ||
               !endpoint.getPathParameters().isEmpty() ||
               endpoint.getMethod().equals("POST") ||
               endpoint.getMethod().equals("PUT") ||
               endpoint.getMethod().equals("PATCH");
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int totalTests = 0;

        logger.info("Starting Command Injection scan on: " + endpoint);

        // Test Case 1: Error-based command injection
        CmdInjTestResult errorResult = testErrorBasedInjection(endpoint, httpClient, context);
        totalTests += errorResult.testsExecuted();
        if (errorResult.vulnerability().isPresent()) {
            vulnerabilities.add(errorResult.vulnerability().get());
        }

        // Test Case 2: Output-based command injection
        if (vulnerabilities.isEmpty()) {
            CmdInjTestResult outputResult = testOutputBasedInjection(endpoint, httpClient, context);
            totalTests += outputResult.testsExecuted();
            if (outputResult.vulnerability().isPresent()) {
                vulnerabilities.add(outputResult.vulnerability().get());
            }
        }

        // Test Case 3: Time-based blind command injection
        if (vulnerabilities.isEmpty()) {
            CmdInjTestResult timeResult = testTimeBasedInjection(endpoint, httpClient, context);
            totalTests += timeResult.testsExecuted();
            if (timeResult.vulnerability().isPresent()) {
                vulnerabilities.add(timeResult.vulnerability().get());
            }
        }

        // Test Case 4: Body parameter command injection
        if (vulnerabilities.isEmpty() && hasRequestBody(endpoint)) {
            CmdInjTestResult bodyResult = testBodyParameterInjection(endpoint, httpClient, context);
            totalTests += bodyResult.testsExecuted();
            if (bodyResult.vulnerability().isPresent()) {
                vulnerabilities.add(bodyResult.vulnerability().get());
            }
        }

        // Test Case 5: HTTP Header command injection
        if (vulnerabilities.isEmpty()) {
            CmdInjTestResult headerResult = testHeaderParameterInjection(endpoint, httpClient, context);
            totalTests += headerResult.testsExecuted();
            if (headerResult.vulnerability().isPresent()) {
                vulnerabilities.add(headerResult.vulnerability().get());
            }
        }

        return createSuccessResult(endpoint, vulnerabilities, totalTests, startTime);
    }

    /**
     * Test for error-based command injection.
     */
    private CmdInjTestResult testErrorBasedInjection(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing error-based command injection for: " + endpoint);

        int testsExecuted = 0;

        // Filter payloads to remove those with newlines (illegal in URLs)
        List<String> urlSafePayloads = filterPayloadsForUrl(ERROR_BASED_PAYLOADS);

        // Test query parameters (URL-safe payloads only)
        for (ParameterSpec param : endpoint.getQueryParameters()) {
            for (String payload : urlSafePayloads) {
                TestRequest request = createRequestWithParameter(
                    endpoint,
                    context,
                    param.getName(),
                    payload,
                    ParameterLocation.QUERY
                );

                TestResponse response = executeTest(httpClient, request, "Error-based CMDi: " + param.getName());
                testsExecuted++;

                if (containsCommandError(response)) {
                    return new CmdInjTestResult(
                        Optional.of(createErrorBasedVulnerability(endpoint, param.getName(), payload, request, response)),
                        testsExecuted
                    );
                }
            }
        }

        // Test path parameters (URL-safe payloads only)
        for (ParameterSpec param : endpoint.getPathParameters()) {
            for (String payload : urlSafePayloads) {
                TestRequest request = createRequestWithParameter(
                    endpoint,
                    context,
                    param.getName(),
                    payload,
                    ParameterLocation.PATH
                );

                TestResponse response = executeTest(httpClient, request, "Error-based CMDi: " + param.getName());
                testsExecuted++;

                if (containsCommandError(response)) {
                    return new CmdInjTestResult(
                        Optional.of(createErrorBasedVulnerability(endpoint, param.getName(), payload, request, response)),
                        testsExecuted
                    );
                }
            }
        }

        return new CmdInjTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Test for output-based command injection (command output in response).
     */
    private CmdInjTestResult testOutputBasedInjection(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing output-based command injection for: " + endpoint);

        int testsExecuted = 0;

        // Test query parameters
        for (ParameterSpec param : endpoint.getQueryParameters()) {
            for (OutputPayloadPair payloadPair : OUTPUT_BASED_PAYLOADS) {
                TestRequest request = createRequestWithParameter(
                    endpoint,
                    context,
                    param.getName(),
                    payloadPair.payload(),
                    ParameterLocation.QUERY
                );

                TestResponse response = executeTest(httpClient, request, "Output-based CMDi: " + param.getName());
                testsExecuted++;

                if (response.getBody() != null && response.getBody().contains(payloadPair.expectedOutput())) {
                    return new CmdInjTestResult(
                        Optional.of(createOutputBasedVulnerability(endpoint, param.getName(), payloadPair, request, response)),
                        testsExecuted
                    );
                }
            }
        }

        return new CmdInjTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Test for time-based blind command injection.
     */
    private CmdInjTestResult testTimeBasedInjection(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing time-based blind command injection for: " + endpoint);

        int testsExecuted = 0;

        // Test query parameters
        for (ParameterSpec param : endpoint.getQueryParameters()) {
            // Measure baseline response time
            Instant baselineStart = Instant.now();
            TestRequest baselineRequest = createRequestWithParameter(
                endpoint,
                context,
                param.getName(),
                "test",
                ParameterLocation.QUERY
            );
            executeTest(httpClient, baselineRequest, "Time baseline");
            long baselineTime = Duration.between(baselineStart, Instant.now()).toMillis();
            testsExecuted++;

            // Test time-based payloads
            for (String payload : TIME_BASED_PAYLOADS) {
                Instant payloadStart = Instant.now();
                TestRequest request = createRequestWithParameter(
                    endpoint,
                    context,
                    param.getName(),
                    payload,
                    ParameterLocation.QUERY
                );
                TestResponse response = executeTest(httpClient, request, "Time-based CMDi: " + param.getName());
                long payloadTime = Duration.between(payloadStart, Instant.now()).toMillis();
                testsExecuted++;

                // If response is delayed by ~5 seconds, it's vulnerable
                long timeDifference = payloadTime - baselineTime;
                if (timeDifference >= 4500 && timeDifference <= 10000) {
                    return new CmdInjTestResult(
                        Optional.of(createTimeBasedVulnerability(
                            endpoint,
                            param.getName(),
                            payload,
                            request,
                            response,
                            baselineTime,
                            payloadTime
                        )),
                        testsExecuted
                    );
                }
            }
        }

        return new CmdInjTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Test for command injection in request body parameters.
     */
    private CmdInjTestResult testBodyParameterInjection(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing body parameter command injection for: " + endpoint);

        int testsExecuted = 0;

        try {
            Object schemaObj = endpoint.getMetadata().get("requestBodySchema");
            if (schemaObj == null) {
                return new CmdInjTestResult(Optional.empty(), testsExecuted);
            }

            List<String> fieldNames = extractFieldNamesFromSchema(schemaObj);
            if (fieldNames.isEmpty()) {
                return new CmdInjTestResult(Optional.empty(), testsExecuted);
            }

            // Test each field with error-based payloads
            for (String fieldName : fieldNames) {
                for (String payload : ERROR_BASED_PAYLOADS) {
                    TestRequest request = createRequestWithBodyParameter(
                        endpoint,
                        context,
                        fieldName,
                        payload
                    );

                    TestResponse response = executeTest(httpClient, request, "Body CMDi: " + fieldName);
                    testsExecuted++;

                    if (containsCommandError(response)) {
                        return new CmdInjTestResult(
                            Optional.of(createBodyParameterVulnerability(endpoint, fieldName, payload, request, response)),
                            testsExecuted
                        );
                    }
                }
            }

        } catch (Exception e) {
            logger.warning("Failed to test body parameters: " + e.getMessage());
        }

        return new CmdInjTestResult(Optional.empty(), testsExecuted);
    }

    private boolean hasRequestBody(ApiEndpoint endpoint) {
        String method = endpoint.getMethod();
        return (method.equals("POST") || method.equals("PUT") || method.equals("PATCH")) &&
               endpoint.getMetadata().get("requestBodySchema") != null;
    }

    private boolean containsCommandError(TestResponse response) {
        String body = response.getBody();
        if (body == null || body.isEmpty()) {
            return false;
        }

        return COMMAND_ERROR_PATTERNS.stream()
            .anyMatch(pattern -> pattern.matcher(body).find());
    }

    private List<String> extractFieldNamesFromSchema(Object schemaObj) {
        List<String> fieldNames = new ArrayList<>();
        try {
            if (schemaObj instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> schema = (Map<String, Object>) schemaObj;
                Object propertiesObj = schema.get("properties");
                if (propertiesObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> properties = (Map<String, Object>) propertiesObj;
                    fieldNames.addAll(properties.keySet());
                }
            }
        } catch (Exception e) {
            logger.fine("Failed to parse request body schema: " + e.getMessage());
        }
        return fieldNames;
    }

    private TestRequest createRequestWithParameter(
        ApiEndpoint endpoint,
        ScanContext context,
        String paramName,
        String paramValue,
        ParameterLocation location
    ) {
        Map<String, String> queryParams = new HashMap<>();
        String path = endpoint.getPath();

        // First, substitute all path parameters with default values
        for (var pathParam : endpoint.getPathParameters()) {
            String defaultValue = getDefaultValueForParameter(pathParam);
            path = path.replaceAll("\\{" + pathParam.getName() + "\\}", defaultValue);
        }

        // Then, if we're testing a PATH parameter, replace it with the test payload
        if (location == ParameterLocation.QUERY) {
            queryParams.put(paramName, paramValue);
        } else if (location == ParameterLocation.PATH) {
            // Re-replace the specific parameter we're testing with the payload
            path = path.replaceAll(getDefaultValueForParameterByName(endpoint, paramName),
                                   java.util.regex.Matcher.quoteReplacement(paramValue));
        }

        String url = context.buildUrl(path);
        if (!queryParams.isEmpty()) {
            url += "?" + buildQueryString(queryParams);
        }

        return TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();
    }

    /**
     * Get a realistic default value for a parameter based on its name and type.
     */
    private String getDefaultValueForParameter(model.ParameterSpec param) {
        String name = param.getName().toLowerCase();

        // Common ID patterns
        if (name.contains("id") || name.equals("uuid")) {
            return "1";
        }
        if (name.contains("account")) {
            return "12345";
        }
        if (name.contains("user")) {
            return "1";
        }
        if (name.contains("transaction")) {
            return "1";
        }

        // Default based on type
        String type = param.getType();
        if (type != null) {
            if (type.contains("int") || type.contains("long") || type.equals("number")) {
                return "1";
            }
            if (type.equals("string")) {
                return "test";
            }
        }

        return "1";  // Safe numeric default
    }

    /**
     * Get the default value that was used for a specific parameter by name.
     */
    private String getDefaultValueForParameterByName(ApiEndpoint endpoint, String paramName) {
        for (var param : endpoint.getPathParameters()) {
            if (param.getName().equals(paramName)) {
                return getDefaultValueForParameter(param);
            }
        }
        return "1";
    }

    private TestRequest createRequestWithBodyParameter(
        ApiEndpoint endpoint,
        ScanContext context,
        String fieldName,
        String payload
    ) {
        try {
            ObjectNode bodyJson = objectMapper.createObjectNode();
            bodyJson.put(fieldName, payload);

            Object schemaObj = endpoint.getMetadata().get("requestBodySchema");
            if (schemaObj instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> schema = (Map<String, Object>) schemaObj;
                Object propertiesObj = schema.get("properties");
                if (propertiesObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> properties = (Map<String, Object>) propertiesObj;
                    for (String key : properties.keySet()) {
                        if (!key.equals(fieldName) && !bodyJson.has(key)) {
                            bodyJson.put(key, "test");
                        }
                    }
                }
            }

            // Substitute all path parameters with default values
            String path = endpoint.getPath();
            for (var pathParam : endpoint.getPathParameters()) {
                String defaultValue = getDefaultValueForParameter(pathParam);
                path = path.replaceAll("\\{" + pathParam.getName() + "\\}", defaultValue);
            }

            String jsonBody = objectMapper.writeValueAsString(bodyJson);
            return TestRequest.builder()
                .url(context.buildUrl(path))
                .method(endpoint.getMethod())
                .headers(context.getAuthHeaders())
                .addHeader("Content-Type", "application/json")
                .body(jsonBody)
                .build();
        } catch (Exception e) {
            logger.warning("Failed to create body parameter request: " + e.getMessage());

            // Substitute path parameters even in error case
            String path = endpoint.getPath();
            for (var pathParam : endpoint.getPathParameters()) {
                String defaultValue = getDefaultValueForParameter(pathParam);
                path = path.replaceAll("\\{" + pathParam.getName() + "\\}", defaultValue);
            }

            return TestRequest.builder()
                .url(context.buildUrl(path))
                .method(endpoint.getMethod())
                .headers(context.getAuthHeaders())
                .build();
        }
    }

    private String buildQueryString(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (sb.length() > 0) sb.append("&");
            try {
                sb.append(java.net.URLEncoder.encode(entry.getKey(), "UTF-8"))
                  .append("=")
                  .append(java.net.URLEncoder.encode(entry.getValue(), "UTF-8"));
            } catch (java.io.UnsupportedEncodingException e) {
                // UTF-8 is always supported, this should never happen
                sb.append(entry.getKey()).append("=").append(entry.getValue());
            }
        }
        return sb.toString();
    }

    private VulnerabilityReport createErrorBasedVulnerability(
        ApiEndpoint endpoint,
        String paramName,
        String payload,
        TestRequest request,
        TestResponse response
    ) {
        return VulnerabilityReport.builder()
            .type(VulnerabilityReport.VulnerabilityType.COMMAND_INJECTION)
            .severity(Severity.CRITICAL)
            .endpoint(endpoint)
            .title("OS Command Injection - Error-based")
            .description(
                "The endpoint is vulnerable to OS Command Injection. Shell error messages were detected " +
                "in the response when injecting command syntax into the '" + paramName + "' parameter. " +
                "This allows attackers to execute arbitrary system commands on the server."
            )
            .exploitRequest(request)
            .exploitResponse(response)
            .addEvidence("parameter", paramName)
            .addEvidence("payload", payload)
            .addEvidence("statusCode", response.getStatusCode())
            .addRecommendation("Never pass user input directly to system commands")
            .addRecommendation("Use parameterized APIs that don't invoke a shell")
            .addRecommendation("Implement strict input validation with whitelists")
            .addRecommendation("Apply the principle of least privilege for application processes")
            .addRecommendation("Use sandboxing or containerization to limit damage")
            .reproductionSteps(
                "1. Send " + endpoint.getMethod() + " request to " + request.getUrl() + "\n" +
                "2. Set parameter '" + paramName + "' to: " + payload + "\n" +
                "3. Observe shell error or command output in response"
            )
            .build();
    }

    private VulnerabilityReport createOutputBasedVulnerability(
        ApiEndpoint endpoint,
        String paramName,
        OutputPayloadPair payloadPair,
        TestRequest request,
        TestResponse response
    ) {
        return VulnerabilityReport.builder()
            .type(VulnerabilityReport.VulnerabilityType.COMMAND_INJECTION)
            .severity(Severity.CRITICAL)
            .endpoint(endpoint)
            .title("OS Command Injection - Output-based")
            .description(
                "The endpoint is vulnerable to OS Command Injection. Command output ('" +
                payloadPair.expectedOutput() + "') was detected in the response when injecting " +
                "command syntax into the '" + paramName + "' parameter."
            )
            .exploitRequest(request)
            .exploitResponse(response)
            .addEvidence("parameter", paramName)
            .addEvidence("payload", payloadPair.payload())
            .addEvidence("expectedOutput", payloadPair.expectedOutput())
            .addRecommendation("Never pass user input directly to system commands")
            .addRecommendation("Use parameterized APIs that don't invoke a shell")
            .addRecommendation("Implement strict input validation with whitelists")
            .reproductionSteps(
                "1. Send " + endpoint.getMethod() + " request to " + request.getUrl() + "\n" +
                "2. Observe command output in response"
            )
            .build();
    }

    private VulnerabilityReport createTimeBasedVulnerability(
        ApiEndpoint endpoint,
        String paramName,
        String payload,
        TestRequest request,
        TestResponse response,
        long baselineTime,
        long payloadTime
    ) {
        long delay = payloadTime - baselineTime;
        return VulnerabilityReport.builder()
            .type(VulnerabilityReport.VulnerabilityType.COMMAND_INJECTION)
            .severity(Severity.HIGH)
            .endpoint(endpoint)
            .title("OS Command Injection - Time-based Blind")
            .description(
                "The endpoint is vulnerable to Time-based Blind Command Injection. " +
                "The application's response was delayed by approximately " + (delay / 1000.0) +
                " seconds when a time-delay command was injected into the '" + paramName + "' parameter."
            )
            .exploitRequest(request)
            .exploitResponse(response)
            .addEvidence("parameter", paramName)
            .addEvidence("payload", payload)
            .addEvidence("baselineTime", baselineTime + "ms")
            .addEvidence("payloadTime", payloadTime + "ms")
            .addEvidence("delay", delay + "ms")
            .addRecommendation("Never pass user input directly to system commands")
            .addRecommendation("Use parameterized APIs that don't invoke a shell")
            .addRecommendation("Implement strict input validation with whitelists")
            .reproductionSteps(
                "1. Measure baseline response time (~" + baselineTime + "ms)\n" +
                "2. Send request with time-delay payload\n" +
                "3. Observe delayed response (~" + payloadTime + "ms)"
            )
            .build();
    }

    private VulnerabilityReport createBodyParameterVulnerability(
        ApiEndpoint endpoint,
        String fieldName,
        String payload,
        TestRequest request,
        TestResponse response
    ) {
        return VulnerabilityReport.builder()
            .type(VulnerabilityReport.VulnerabilityType.COMMAND_INJECTION)
            .severity(Severity.CRITICAL)
            .endpoint(endpoint)
            .title("OS Command Injection - Request Body Parameter")
            .description(
                "The endpoint is vulnerable to OS Command Injection in the request body field '" + fieldName + "'. " +
                "Shell error messages were detected when injecting command syntax into the JSON body."
            )
            .exploitRequest(request)
            .exploitResponse(response)
            .addEvidence("bodyField", fieldName)
            .addEvidence("payload", payload)
            .addEvidence("requestBody", request.getBody())
            .addRecommendation("Never pass user input directly to system commands")
            .addRecommendation("Use parameterized APIs that don't invoke a shell")
            .addRecommendation("Implement strict input validation with whitelists")
            .reproductionSteps(
                "1. Send " + endpoint.getMethod() + " request to " + request.getUrl() + "\n" +
                "2. Include JSON body with field '" + fieldName + "' set to: " + payload + "\n" +
                "3. Observe shell error in response"
            )
            .build();
    }

    /**
     * Test for command injection in HTTP headers.
     * Headers are often passed to backend commands, logging systems, or external processes.
     */
    private CmdInjTestResult testHeaderParameterInjection(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing header parameter command injection for: " + endpoint);

        int testsExecuted = 0;

        // Common headers that might be vulnerable to command injection
        List<String> testHeaders = List.of(
            "X-Consent-Id",
            "X-Requesting-Bank",
            "X-Payment-Consent-Id",
            "X-Product-Agreement-Consent-Id",
            "X-Fapi-Interaction-Id",
            "X-Fapi-Customer-Ip-Address",
            "X-Request-Id",
            "X-Correlation-Id",
            "X-Client-Id",
            "X-Forwarded-For",
            "User-Agent",
            "Referer"
        );

        // Substitute all path parameters with default values
        String path = endpoint.getPath();
        for (var pathParam : endpoint.getPathParameters()) {
            String defaultValue = getDefaultValueForParameter(pathParam);
            path = path.replaceAll("\\{" + pathParam.getName() + "\\}", defaultValue);
        }

        String url = context.buildUrl(path);

        // Filter payloads to remove those with newlines (illegal in HTTP headers)
        List<String> headerSafePayloads = filterPayloadsForUrl(ERROR_BASED_PAYLOADS);

        for (String headerName : testHeaders) {
            for (String payload : headerSafePayloads) {
                Map<String, String> headers = new HashMap<>(context.getAuthHeaders());
                headers.put(headerName, payload);

                TestRequest request = TestRequest.builder()
                    .url(url)
                    .method(endpoint.getMethod())
                    .headers(headers)
                    .build();

                TestResponse response = executeTest(httpClient, request, "Header CMDi: " + headerName);
                testsExecuted++;

                if (containsCommandError(response)) {
                    return new CmdInjTestResult(
                        Optional.of(createHeaderParameterVulnerability(endpoint, headerName, payload, request, response)),
                        testsExecuted
                    );
                }
            }
        }

        return new CmdInjTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Create vulnerability report for header parameter command injection.
     */
    private VulnerabilityReport createHeaderParameterVulnerability(
        ApiEndpoint endpoint,
        String headerName,
        String payload,
        TestRequest request,
        TestResponse response
    ) {
        return VulnerabilityReport.builder()
            .type(VulnerabilityReport.VulnerabilityType.COMMAND_INJECTION)
            .severity(Severity.CRITICAL)
            .endpoint(endpoint)
            .title("OS Command Injection - HTTP Header")
            .description(
                "The endpoint is vulnerable to OS Command Injection in the HTTP header '" + headerName + "'. " +
                "Shell error messages were detected in the response when injecting command syntax into the header. " +
                "This allows attackers to execute arbitrary system commands on the server. " +
                "Headers are commonly passed to backend processes, logging systems, or monitoring tools " +
                "without proper sanitization, making them a prime target for command injection attacks."
            )
            .exploitRequest(request)
            .exploitResponse(response)
            .addEvidence("headerName", headerName)
            .addEvidence("payload", payload)
            .addEvidence("statusCode", response.getStatusCode())
            .addRecommendation("Never pass HTTP header values directly to system commands")
            .addRecommendation("Use parameterized APIs that don't invoke a shell")
            .addRecommendation("Implement strict input validation with whitelists for all headers")
            .addRecommendation("Avoid using headers in command-line operations, logs processed by shell scripts, or external tool invocations")
            .addRecommendation("Apply the principle of least privilege for application processes")
            .addRecommendation("Use sandboxing or containerization to limit damage")
            .reproductionSteps(
                "1. Send " + endpoint.getMethod() + " request to " + request.getUrl() + "\n" +
                "2. Include header '" + headerName + ": " + payload + "'\n" +
                "3. Observe shell error or command output in response"
            )
            .build();
    }

    private enum ParameterLocation {
        QUERY, PATH, BODY, HEADER
    }

    private record OutputPayloadPair(String payload, String expectedOutput) {}

    private record CmdInjTestResult(
        Optional<VulnerabilityReport> vulnerability,
        int testsExecuted
    ) {}
}
