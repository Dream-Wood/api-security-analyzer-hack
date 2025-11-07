package active.scanner.sqlinjection;

import active.http.HttpClient;
import active.model.ApiEndpoint;
import active.model.TestRequest;
import active.model.TestResponse;
import active.model.VulnerabilityReport;
import active.scanner.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import model.ParameterSpec;
import model.Severity;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Scanner for detecting SQL Injection vulnerabilities.
 *
 * <p>SQL Injection occurs when user input is improperly sanitized and inserted
 * into SQL queries, allowing attackers to manipulate the database. This scanner tests for:
 * <ul>
 *   <li>Error-based SQL injection (database error messages in responses)</li>
 *   <li>Boolean-based blind SQL injection (different responses for true/false conditions)</li>
 *   <li>Time-based blind SQL injection (delays in response time)</li>
 *   <li>Union-based SQL injection (additional data extraction)</li>
 * </ul>
 *
 * <p>Common attack vectors include:
 * <ul>
 *   <li>Query parameters (e.g., ?id=1)</li>
 *   <li>Path parameters (e.g., /users/{id})</li>
 *   <li>Request body fields (JSON, form data)</li>
 *   <li>HTTP headers (User-Agent, Referer, etc.)</li>
 * </ul>
 */
public final class SqlInjectionScanner extends AbstractScanner {

    private static final String SCANNER_ID = "sql-injection-scanner";
    private static final String SCANNER_NAME = "SQL Injection Scanner";
    private static final String SCANNER_DESCRIPTION =
        "Detects SQL Injection vulnerabilities including error-based, boolean-based, and time-based blind SQLi";

    // SQL error patterns for different databases
    private static final List<Pattern> SQL_ERROR_PATTERNS = List.of(
        // MySQL
        Pattern.compile("SQL syntax.*MySQL", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Warning.*mysql_.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("valid MySQL result", Pattern.CASE_INSENSITIVE),
        Pattern.compile("MySqlClient\\.", Pattern.CASE_INSENSITIVE),

        // PostgreSQL
        Pattern.compile("PostgreSQL.*ERROR", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Warning.*\\Wpg_.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("valid PostgreSQL result", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Npgsql\\.", Pattern.CASE_INSENSITIVE),

        // MSSQL
        Pattern.compile("Driver.*SQL[\\-\\_\\ ]*Server", Pattern.CASE_INSENSITIVE),
        Pattern.compile("OLE DB.*SQL Server", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bSQL Server.*Driver", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Warning.*mssql_.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bSQL Server.*[0-9a-fA-F]{8}", Pattern.CASE_INSENSITIVE),
        Pattern.compile("System\\.Data\\.SqlClient\\.SqlException", Pattern.CASE_INSENSITIVE),

        // Oracle
        Pattern.compile("\\bORA-[0-9][0-9][0-9][0-9]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Oracle error", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Oracle.*Driver", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Warning.*\\Woci_.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Warning.*\\Wora_.*", Pattern.CASE_INSENSITIVE),

        // Generic
        Pattern.compile("JDBC.*SQLException", Pattern.CASE_INSENSITIVE),
        Pattern.compile("SQLite.*Exception", Pattern.CASE_INSENSITIVE),
        Pattern.compile("SQLException", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Syntax error.*in query expression", Pattern.CASE_INSENSITIVE),
        Pattern.compile("unclosed quotation mark", Pattern.CASE_INSENSITIVE),
        Pattern.compile("quoted string not properly terminated", Pattern.CASE_INSENSITIVE)
    );

    // Error-based payloads
    private static final List<String> ERROR_BASED_PAYLOADS = List.of(
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "\" OR 1=1--",
        "') OR ('1'='1",
        "\") OR (\"1\"=\"1",
        "1' AND '1'='2",
        "1\" AND \"1\"=\"2",
        "admin'--",
        "admin\"--",
        "' UNION SELECT NULL--",
        "\" UNION SELECT NULL--"
    );

    // Boolean-based blind SQLi payloads
    private static final List<BooleanPayloadPair> BOOLEAN_PAYLOADS = List.of(
        new BooleanPayloadPair("1' AND '1'='1", "1' AND '1'='2"),
        new BooleanPayloadPair("1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"),
        new BooleanPayloadPair("1 AND 1=1", "1 AND 1=2"),
        new BooleanPayloadPair("' OR 'x'='x", "' OR 'x'='y"),
        new BooleanPayloadPair("\" OR \"x\"=\"x", "\" OR \"x\"=\"y")
    );

    // Time-based blind SQLi payloads (should cause ~5 second delay)
    private static final List<String> TIME_BASED_PAYLOADS = List.of(
        // MySQL
        "' AND SLEEP(5)--",
        "\" AND SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "1\" AND SLEEP(5)--",

        // PostgreSQL
        "'; SELECT pg_sleep(5)--",
        "\"; SELECT pg_sleep(5)--",

        // MSSQL
        "'; WAITFOR DELAY '0:0:5'--",
        "\"; WAITFOR DELAY '0:0:5'--",

        // Oracle
        "' AND DBMS_LOCK.SLEEP(5)--",
        "\" AND DBMS_LOCK.SLEEP(5)--"
    );

    private final ObjectMapper objectMapper = new ObjectMapper();

    public SqlInjectionScanner() {
        super();
    }

    public SqlInjectionScanner(ScannerConfig config) {
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
        return List.of(VulnerabilityReport.VulnerabilityType.SQL_INJECTION);
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // SQL injection can occur in any endpoint that processes parameters
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

        logger.info("Starting SQL Injection scan on: " + endpoint);

        // Test Case 1: Error-based SQL injection
        SqliTestResult errorBasedResult = testErrorBasedSqli(endpoint, httpClient, context);
        totalTests += errorBasedResult.testsExecuted();
        if (errorBasedResult.vulnerability().isPresent()) {
            vulnerabilities.add(errorBasedResult.vulnerability().get());
        }

        // Test Case 2: Boolean-based blind SQL injection
        if (vulnerabilities.isEmpty()) {
            SqliTestResult booleanResult = testBooleanBasedSqli(endpoint, httpClient, context);
            totalTests += booleanResult.testsExecuted();
            if (booleanResult.vulnerability().isPresent()) {
                vulnerabilities.add(booleanResult.vulnerability().get());
            }
        }

        // Test Case 3: Time-based blind SQL injection
        if (vulnerabilities.isEmpty()) {
            SqliTestResult timeBasedResult = testTimeBasedSqli(endpoint, httpClient, context);
            totalTests += timeBasedResult.testsExecuted();
            if (timeBasedResult.vulnerability().isPresent()) {
                vulnerabilities.add(timeBasedResult.vulnerability().get());
            }
        }

        // Test Case 4: Body parameter SQL injection (for POST/PUT/PATCH)
        if (vulnerabilities.isEmpty() && hasRequestBody(endpoint)) {
            SqliTestResult bodyResult = testBodyParameterSqli(endpoint, httpClient, context);
            totalTests += bodyResult.testsExecuted();
            if (bodyResult.vulnerability().isPresent()) {
                vulnerabilities.add(bodyResult.vulnerability().get());
            }
        }

        // Test Case 5: HTTP Header SQL injection
        if (vulnerabilities.isEmpty() && hasCustomHeaders(endpoint)) {
            SqliTestResult headerResult = testHeaderParameterSqli(endpoint, httpClient, context);
            totalTests += headerResult.testsExecuted();
            if (headerResult.vulnerability().isPresent()) {
                vulnerabilities.add(headerResult.vulnerability().get());
            }
        }

        return createSuccessResult(endpoint, vulnerabilities, totalTests, startTime);
    }

    /**
     * Check if endpoint has request body schema.
     */
    private boolean hasRequestBody(ApiEndpoint endpoint) {
        String method = endpoint.getMethod();
        boolean isBodyMethod = method.equals("POST") || method.equals("PUT") || method.equals("PATCH");

        if (!isBodyMethod) {
            return false;
        }

        // Check if request body schema is present in metadata
        Object schemaObj = endpoint.getMetadata().get("requestBodySchema");
        return schemaObj != null;
    }

    /**
     * Test for SQL injection in request body parameters.
     */
    private SqliTestResult testBodyParameterSqli(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing body parameter SQL injection for: " + endpoint);

        int testsExecuted = 0;

        try {
            // Get request body schema from metadata
            Object schemaObj = endpoint.getMetadata().get("requestBodySchema");
            if (schemaObj == null) {
                return new SqliTestResult(Optional.empty(), testsExecuted);
            }

            // Parse the schema to extract field names
            List<String> fieldNames = extractFieldNamesFromSchema(schemaObj);

            if (fieldNames.isEmpty()) {
                logger.fine("No testable fields found in request body schema");
                return new SqliTestResult(Optional.empty(), testsExecuted);
            }

            logger.fine("Found " + fieldNames.size() + " testable body fields: " + fieldNames);

            // Test each field with error-based SQL injection payloads
            for (String fieldName : fieldNames) {
                for (String payload : ERROR_BASED_PAYLOADS) {
                    TestRequest request = createRequestWithBodyParameter(
                        endpoint,
                        context,
                        fieldName,
                        payload
                    );

                    TestResponse response = executeTest(httpClient, request, "Body SQLi: " + fieldName);
                    testsExecuted++;

                    if (containsSqlError(response)) {
                        return new SqliTestResult(
                            Optional.of(createBodyParameterVulnerability(endpoint, fieldName, payload, request, response)),
                            testsExecuted
                        );
                    }
                }
            }

        } catch (Exception e) {
            logger.warning("Failed to test body parameters: " + e.getMessage());
        }

        return new SqliTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Extract field names from request body schema.
     */
    private List<String> extractFieldNamesFromSchema(Object schemaObj) {
        List<String> fieldNames = new ArrayList<>();

        try {
            if (schemaObj instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> schema = (Map<String, Object>) schemaObj;

                // Look for "properties" in the schema
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

    /**
     * Create a test request with SQL injection payload in JSON body.
     */
    private TestRequest createRequestWithBodyParameter(
        ApiEndpoint endpoint,
        ScanContext context,
        String fieldName,
        String payload
    ) {
        try {
            // Create a simple JSON body with the payload
            ObjectNode bodyJson = objectMapper.createObjectNode();
            bodyJson.put(fieldName, payload);

            // Add other fields with default values if available from schema
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
                            // Add default values for other required fields
                            bodyJson.put(key, "test");
                        }
                    }
                }
            }

            String jsonBody = objectMapper.writeValueAsString(bodyJson);
            String url = context.buildUrl(endpoint.getPath());

            return TestRequest.builder()
                .url(url)
                .method(endpoint.getMethod())
                .headers(context.getAuthHeaders())
                .addHeader("Content-Type", "application/json")
                .body(jsonBody)
                .build();

        } catch (Exception e) {
            logger.warning("Failed to create body parameter request: " + e.getMessage());
            // Fallback to simple request
            String url = context.buildUrl(endpoint.getPath());
            return TestRequest.builder()
                .url(url)
                .method(endpoint.getMethod())
                .headers(context.getAuthHeaders())
                .build();
        }
    }

    /**
     * Create vulnerability report for body parameter SQL injection.
     */
    private VulnerabilityReport createBodyParameterVulnerability(
        ApiEndpoint endpoint,
        String fieldName,
        String payload,
        TestRequest request,
        TestResponse response
    ) {
        return VulnerabilityReport.builder()
            .type(VulnerabilityReport.VulnerabilityType.SQL_INJECTION)
            .severity(Severity.CRITICAL)
            .endpoint(endpoint)
            .title("SQL Injection - Request Body Parameter")
            .description(
                "The endpoint is vulnerable to SQL Injection in the request body field '" + fieldName + "'. " +
                "Database error messages were detected in the response when injecting SQL syntax into the JSON body. " +
                "This indicates that user input from the request body is not properly sanitized before being used in SQL queries."
            )
            .exploitRequest(request)
            .exploitResponse(response)
            .addEvidence("bodyField", fieldName)
            .addEvidence("payload", payload)
            .addEvidence("requestBody", request.getBody())
            .addEvidence("statusCode", response.getStatusCode())
            .addRecommendation("Use parameterized queries (prepared statements) instead of string concatenation")
            .addRecommendation("Implement input validation and sanitization for all request body fields")
            .addRecommendation("Use ORM frameworks that provide SQL injection protection")
            .addRecommendation("Apply the principle of least privilege for database users")
            .addRecommendation("Implement Web Application Firewall (WAF) rules to detect SQL injection attempts")
            .addRecommendation("Never display detailed database errors to end users")
            .reproductionSteps(
                "1. Send " + endpoint.getMethod() + " request to " + request.getUrl() + "\n" +
                "2. Include JSON body with field '" + fieldName + "' set to: " + payload + "\n" +
                "3. Observe SQL error in response body"
            )
            .build();
    }

    /**
     * Test for error-based SQL injection by injecting payloads and checking for SQL errors.
     */
    private SqliTestResult testErrorBasedSqli(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing error-based SQL injection for: " + endpoint);

        int testsExecuted = 0;

        // Test query parameters
        for (ParameterSpec param : endpoint.getQueryParameters()) {
            for (String payload : ERROR_BASED_PAYLOADS) {
                TestRequest request = createRequestWithParameter(
                    endpoint,
                    context,
                    param.getName(),
                    payload,
                    ParameterLocation.QUERY
                );

                TestResponse response = executeTest(httpClient, request, "Error-based SQLi: " + param.getName());
                testsExecuted++;

                if (containsSqlError(response)) {
                    return new SqliTestResult(
                        Optional.of(createErrorBasedVulnerability(endpoint, param.getName(), payload, request, response)),
                        testsExecuted
                    );
                }
            }
        }

        // Test path parameters
        for (ParameterSpec param : endpoint.getPathParameters()) {
            for (String payload : ERROR_BASED_PAYLOADS) {
                TestRequest request = createRequestWithParameter(
                    endpoint,
                    context,
                    param.getName(),
                    payload,
                    ParameterLocation.PATH
                );

                TestResponse response = executeTest(httpClient, request, "Error-based SQLi: " + param.getName());
                testsExecuted++;

                if (containsSqlError(response)) {
                    return new SqliTestResult(
                        Optional.of(createErrorBasedVulnerability(endpoint, param.getName(), payload, request, response)),
                        testsExecuted
                    );
                }
            }
        }

        return new SqliTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Test for boolean-based blind SQL injection by comparing responses to true/false conditions.
     */
    private SqliTestResult testBooleanBasedSqli(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing boolean-based blind SQL injection for: " + endpoint);

        int testsExecuted = 0;

        // Test query parameters
        for (ParameterSpec param : endpoint.getQueryParameters()) {
            // Get baseline response
            TestRequest baselineRequest = createRequestWithParameter(
                endpoint,
                context,
                param.getName(),
                "1",
                ParameterLocation.QUERY
            );
            TestResponse baselineResponse = executeTest(httpClient, baselineRequest, "Baseline");
            testsExecuted++;

            for (BooleanPayloadPair payloadPair : BOOLEAN_PAYLOADS) {
                // Test TRUE condition
                TestRequest trueRequest = createRequestWithParameter(
                    endpoint,
                    context,
                    param.getName(),
                    payloadPair.truePayload(),
                    ParameterLocation.QUERY
                );
                TestResponse trueResponse = executeTest(httpClient, trueRequest, "Boolean TRUE");
                testsExecuted++;

                // Test FALSE condition
                TestRequest falseRequest = createRequestWithParameter(
                    endpoint,
                    context,
                    param.getName(),
                    payloadPair.falsePayload(),
                    ParameterLocation.QUERY
                );
                TestResponse falseResponse = executeTest(httpClient, falseRequest, "Boolean FALSE");
                testsExecuted++;

                // If TRUE response matches baseline but FALSE response differs significantly, it's vulnerable
                if (responsesAreSimilar(baselineResponse, trueResponse) &&
                    !responsesAreSimilar(baselineResponse, falseResponse)) {

                    return new SqliTestResult(
                        Optional.of(createBooleanBasedVulnerability(
                            endpoint,
                            param.getName(),
                            payloadPair,
                            trueRequest,
                            falseRequest,
                            trueResponse,
                            falseResponse
                        )),
                        testsExecuted
                    );
                }
            }
        }

        return new SqliTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Test for time-based blind SQL injection by injecting delay payloads.
     */
    private SqliTestResult testTimeBasedSqli(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing time-based blind SQL injection for: " + endpoint);

        int testsExecuted = 0;

        // Test query parameters
        for (ParameterSpec param : endpoint.getQueryParameters()) {
            // Measure baseline response time
            Instant baselineStart = Instant.now();
            TestRequest baselineRequest = createRequestWithParameter(
                endpoint,
                context,
                param.getName(),
                "1",
                ParameterLocation.QUERY
            );
            TestResponse baselineResponse = executeTest(httpClient, baselineRequest, "Time baseline");
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
                TestResponse response = executeTest(httpClient, request, "Time-based SQLi: " + param.getName());
                long payloadTime = Duration.between(payloadStart, Instant.now()).toMillis();
                testsExecuted++;

                // If response is delayed by ~5 seconds compared to baseline, it's vulnerable
                long timeDifference = payloadTime - baselineTime;
                if (timeDifference >= 4500 && timeDifference <= 10000) { // 4.5-10 seconds (allowing for network variance)
                    return new SqliTestResult(
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

        return new SqliTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Check if response body contains SQL error messages.
     */
    private boolean containsSqlError(TestResponse response) {
        String body = response.getBody();
        if (body == null || body.isEmpty()) {
            return false;
        }

        return SQL_ERROR_PATTERNS.stream()
            .anyMatch(pattern -> pattern.matcher(body).find());
    }

    /**
     * Compare two responses to determine if they are similar.
     */
    private boolean responsesAreSimilar(TestResponse r1, TestResponse r2) {
        // Check status code
        if (r1.getStatusCode() != r2.getStatusCode()) {
            return false;
        }

        // Check response body length (allow 10% difference)
        int len1 = r1.getBody() != null ? r1.getBody().length() : 0;
        int len2 = r2.getBody() != null ? r2.getBody().length() : 0;

        if (len1 == 0 && len2 == 0) {
            return true;
        }

        double difference = Math.abs(len1 - len2) / (double) Math.max(len1, len2);
        return difference <= 0.1; // 10% threshold
    }

    /**
     * Create a test request with a parameter value.
     */
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

    private String buildQueryString(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (sb.length() > 0) {
                sb.append("&");
            }
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
            .type(VulnerabilityReport.VulnerabilityType.SQL_INJECTION)
            .severity(Severity.CRITICAL)
            .endpoint(endpoint)
            .title("SQL Injection - Error-based")
            .description(
                "The endpoint is vulnerable to SQL Injection. Database error messages were detected " +
                "in the response when injecting SQL syntax into the '" + paramName + "' parameter. " +
                "This indicates that user input is not properly sanitized before being used in SQL queries."
            )
            .exploitRequest(request)
            .exploitResponse(response)
            .addEvidence("parameter", paramName)
            .addEvidence("payload", payload)
            .addEvidence("statusCode", response.getStatusCode())
            .addRecommendation("Use parameterized queries (prepared statements) instead of string concatenation")
            .addRecommendation("Implement input validation and sanitization for all user inputs")
            .addRecommendation("Use ORM frameworks that provide SQL injection protection")
            .addRecommendation("Apply the principle of least privilege for database users")
            .addRecommendation("Implement Web Application Firewall (WAF) rules to detect SQL injection attempts")
            .addRecommendation("Never display detailed database errors to end users")
            .reproductionSteps(
                "1. Send " + endpoint.getMethod() + " request to " + request.getUrl() + "\n" +
                "2. Set parameter '" + paramName + "' to: " + payload + "\n" +
                "3. Observe SQL error in response body"
            )
            .build();
    }

    private VulnerabilityReport createBooleanBasedVulnerability(
        ApiEndpoint endpoint,
        String paramName,
        BooleanPayloadPair payloads,
        TestRequest trueRequest,
        TestRequest falseRequest,
        TestResponse trueResponse,
        TestResponse falseResponse
    ) {
        return VulnerabilityReport.builder()
            .type(VulnerabilityReport.VulnerabilityType.SQL_INJECTION)
            .severity(Severity.HIGH)
            .endpoint(endpoint)
            .title("SQL Injection - Boolean-based Blind")
            .description(
                "The endpoint is vulnerable to Boolean-based Blind SQL Injection in the '" + paramName + "' parameter. " +
                "The application returns different responses for TRUE and FALSE SQL conditions, " +
                "which allows attackers to extract data from the database by asking yes/no questions."
            )
            .exploitRequest(trueRequest)
            .exploitResponse(trueResponse)
            .addEvidence("parameter", paramName)
            .addEvidence("truePayload", payloads.truePayload())
            .addEvidence("falsePayload", payloads.falsePayload())
            .addEvidence("trueStatusCode", trueResponse.getStatusCode())
            .addEvidence("falseStatusCode", falseResponse.getStatusCode())
            .addEvidence("trueResponseLength", trueResponse.getBody() != null ? trueResponse.getBody().length() : 0)
            .addEvidence("falseResponseLength", falseResponse.getBody() != null ? falseResponse.getBody().length() : 0)
            .addRecommendation("Use parameterized queries (prepared statements) instead of string concatenation")
            .addRecommendation("Implement input validation and sanitization for all user inputs")
            .addRecommendation("Use ORM frameworks that provide SQL injection protection")
            .addRecommendation("Implement rate limiting to slow down blind SQLi exploitation attempts")
            .reproductionSteps(
                "1. Send TRUE condition: " + trueRequest.getUrl() + "\n" +
                "2. Observe response (status: " + trueResponse.getStatusCode() + ")\n" +
                "3. Send FALSE condition: " + falseRequest.getUrl() + "\n" +
                "4. Observe different response (status: " + falseResponse.getStatusCode() + ")"
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
            .type(VulnerabilityReport.VulnerabilityType.SQL_INJECTION)
            .severity(Severity.HIGH)
            .endpoint(endpoint)
            .title("SQL Injection - Time-based Blind")
            .description(
                "The endpoint is vulnerable to Time-based Blind SQL Injection in the '" + paramName + "' parameter. " +
                "The application's response was delayed by approximately " + (delay / 1000.0) + " seconds when " +
                "a time-delay SQL function was injected. This allows attackers to extract data from the database " +
                "by measuring response times."
            )
            .exploitRequest(request)
            .exploitResponse(response)
            .addEvidence("parameter", paramName)
            .addEvidence("payload", payload)
            .addEvidence("baselineTime", baselineTime + "ms")
            .addEvidence("payloadTime", payloadTime + "ms")
            .addEvidence("delay", delay + "ms")
            .addRecommendation("Use parameterized queries (prepared statements) instead of string concatenation")
            .addRecommendation("Implement input validation and sanitization for all user inputs")
            .addRecommendation("Use ORM frameworks that provide SQL injection protection")
            .addRecommendation("Set query timeout limits to prevent long-running malicious queries")
            .addRecommendation("Monitor and alert on unusually slow database queries")
            .reproductionSteps(
                "1. Send baseline request and measure response time (~" + baselineTime + "ms)\n" +
                "2. Send request with time-delay payload: " + request.getUrl() + "\n" +
                "3. Observe delayed response (~" + payloadTime + "ms, delay: ~" + delay + "ms)"
            )
            .build();
    }

    /**
     * Check if endpoint has custom headers that could be tested.
     */
    private boolean hasCustomHeaders(ApiEndpoint endpoint) {
        // Check if endpoint has custom headers in metadata or security requirements
        Object headersObj = endpoint.getMetadata().get("headerParameters");
        if (headersObj instanceof List) {
            @SuppressWarnings("unchecked")
            List<?> headers = (List<?>) headersObj;
            return !headers.isEmpty();
        }

        // Common custom headers used in APIs (especially banking/fintech)
        // These are often passed to backend systems and might be vulnerable
        return true; // We'll test common headers even if not documented
    }

    /**
     * Test for SQL injection in HTTP headers.
     * Many APIs pass custom headers to backend systems (databases, logs) without sanitization.
     */
    private SqliTestResult testHeaderParameterSqli(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing header parameter SQL injection for: " + endpoint);

        int testsExecuted = 0;

        // Common custom headers that might be vulnerable
        // Especially relevant for banking/fintech APIs
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
            "User-Agent",
            "Referer"
        );

        String url = context.buildUrl(endpoint.getPath());

        for (String headerName : testHeaders) {
            for (String payload : ERROR_BASED_PAYLOADS) {
                Map<String, String> headers = new HashMap<>(context.getAuthHeaders());
                headers.put(headerName, payload);

                TestRequest request = TestRequest.builder()
                    .url(url)
                    .method(endpoint.getMethod())
                    .headers(headers)
                    .build();

                TestResponse response = executeTest(httpClient, request, "Header SQLi: " + headerName);
                testsExecuted++;

                if (containsSqlError(response)) {
                    return new SqliTestResult(
                        Optional.of(createHeaderParameterVulnerability(endpoint, headerName, payload, request, response)),
                        testsExecuted
                    );
                }
            }
        }

        return new SqliTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Create vulnerability report for header parameter SQL injection.
     */
    private VulnerabilityReport createHeaderParameterVulnerability(
        ApiEndpoint endpoint,
        String headerName,
        String payload,
        TestRequest request,
        TestResponse response
    ) {
        return VulnerabilityReport.builder()
            .type(VulnerabilityReport.VulnerabilityType.SQL_INJECTION)
            .severity(Severity.CRITICAL)
            .endpoint(endpoint)
            .title("SQL Injection - HTTP Header Parameter")
            .description(
                "The endpoint is vulnerable to SQL Injection in the HTTP header '" + headerName + "'. " +
                "Database error messages were detected in the response when injecting SQL syntax into the header. " +
                "This indicates that the header value is not properly sanitized before being used in SQL queries. " +
                "This is particularly dangerous as headers are often logged, passed to backend systems, " +
                "or used for tracking/correlation purposes without proper validation."
            )
            .exploitRequest(request)
            .exploitResponse(response)
            .addEvidence("headerName", headerName)
            .addEvidence("payload", payload)
            .addEvidence("statusCode", response.getStatusCode())
            .addRecommendation("Never use HTTP header values directly in SQL queries")
            .addRecommendation("Use parameterized queries (prepared statements) for all database operations")
            .addRecommendation("Implement strict input validation for all HTTP headers")
            .addRecommendation("Avoid logging or storing raw header values in databases")
            .addRecommendation("Use ORM frameworks that provide SQL injection protection")
            .addRecommendation("Apply the principle of least privilege for database users")
            .addRecommendation("Never display detailed database errors to end users")
            .reproductionSteps(
                "1. Send " + endpoint.getMethod() + " request to " + request.getUrl() + "\n" +
                "2. Include header '" + headerName + ": " + payload + "'\n" +
                "3. Observe SQL error in response body"
            )
            .build();
    }

    /**
     * Location of a parameter in the request.
     */
    private enum ParameterLocation {
        QUERY, PATH, BODY, HEADER
    }

    /**
     * Pair of TRUE and FALSE SQL injection payloads for boolean-based testing.
     */
    private record BooleanPayloadPair(String truePayload, String falsePayload) {}

    /**
     * Result of a SQL injection test case.
     */
    private record SqliTestResult(
        Optional<VulnerabilityReport> vulnerability,
        int testsExecuted
    ) {}
}
