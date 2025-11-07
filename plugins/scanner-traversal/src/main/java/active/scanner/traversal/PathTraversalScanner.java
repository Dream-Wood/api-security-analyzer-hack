package active.scanner.traversal;

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

import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Scanner for detecting Path Traversal (Directory Traversal) vulnerabilities.
 *
 * <p>Path traversal occurs when an application uses user input to construct file paths
 * without proper validation. This scanner tests for:
 * <ul>
 *   <li>Unix/Linux path traversal (../ sequences)</li>
 *   <li>Windows path traversal (..\ sequences)</li>
 *   <li>Absolute path access</li>
 *   <li>URL-encoded and double-encoded traversal</li>
 *   <li>Access to sensitive system files</li>
 * </ul>
 */
public final class PathTraversalScanner extends AbstractScanner {

    private static final String SCANNER_ID = "path-traversal-scanner";
    private static final String SCANNER_NAME = "Path Traversal Scanner";
    private static final String SCANNER_DESCRIPTION =
        "Detects Path Traversal (Directory Traversal) vulnerabilities in file path parameters";

    // Patterns indicating successful file access
    private static final List<Pattern> FILE_CONTENT_PATTERNS = List.of(
        // Unix /etc/passwd
        Pattern.compile("root:.*:0:0:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("daemon:.*:1:1:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("bin:.*:2:2:", Pattern.CASE_INSENSITIVE),

        // Windows hosts file
        Pattern.compile("# Copyright.*Microsoft Corp", Pattern.CASE_INSENSITIVE),
        Pattern.compile("127\\.0\\.0\\.1\\s+localhost", Pattern.CASE_INSENSITIVE),

        // Windows boot.ini
        Pattern.compile("\\[boot loader\\]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\[operating systems\\]", Pattern.CASE_INSENSITIVE),

        // Web server config files
        Pattern.compile("ServerRoot", Pattern.CASE_INSENSITIVE),
        Pattern.compile("DocumentRoot", Pattern.CASE_INSENSITIVE),

        // Application config
        Pattern.compile("jdbc:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("password\\s*=", Pattern.CASE_INSENSITIVE),
        Pattern.compile("api[_-]?key", Pattern.CASE_INSENSITIVE)
    );

    // Path traversal payloads
    private static final List<TraversalPayload> TRAVERSAL_PAYLOADS = List.of(
        // Unix/Linux payloads
        new TraversalPayload("../../../etc/passwd", "/etc/passwd", "Unix passwd file"),
        new TraversalPayload("../../../../etc/passwd", "/etc/passwd", "Unix passwd file (deeper)"),
        new TraversalPayload("../../../../../etc/passwd", "/etc/passwd", "Unix passwd file (deepest)"),
        new TraversalPayload("../../../../../../etc/shadow", "/etc/shadow", "Unix shadow file"),
        new TraversalPayload("/etc/passwd", "/etc/passwd", "Absolute path to passwd"),
        new TraversalPayload("/etc/shadow", "/etc/shadow", "Absolute path to shadow"),

        // Windows payloads
        new TraversalPayload("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "hosts file", "Windows hosts file"),
        new TraversalPayload("..\\..\\..\\..\\windows\\system32\\config\\sam", "SAM file", "Windows SAM file"),
        new TraversalPayload("C:\\Windows\\System32\\drivers\\etc\\hosts", "hosts file", "Windows hosts absolute"),
        new TraversalPayload("C:\\boot.ini", "boot.ini", "Windows boot config"),

        // URL-encoded traversal
        new TraversalPayload("..%2F..%2F..%2Fetc%2Fpasswd", "/etc/passwd", "URL-encoded traversal"),
        new TraversalPayload("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "/etc/passwd", "Full URL-encoded"),

        // Double-encoded traversal
        new TraversalPayload("..%252F..%252F..%252Fetc%252Fpasswd", "/etc/passwd", "Double URL-encoded"),

        // Null byte injection (for older systems)
        new TraversalPayload("../../../etc/passwd%00.jpg", "/etc/passwd", "Null byte bypass"),

        // Mixed encoding
        new TraversalPayload("..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts", "hosts", "Mixed encoding"),

        // Absolute path bypasses
        new TraversalPayload("file:///etc/passwd", "/etc/passwd", "File protocol"),

        // Application-specific paths
        new TraversalPayload("../../WEB-INF/web.xml", "web.xml", "Java web config"),
        new TraversalPayload("../../config/database.yml", "database.yml", "Rails database config"),
        new TraversalPayload("../.env", ".env", "Environment variables"),
        new TraversalPayload("../../.git/config", ".git/config", "Git configuration")
    );

    private final ObjectMapper objectMapper = new ObjectMapper();

    public PathTraversalScanner() {
        super();
    }

    public PathTraversalScanner(ScannerConfig config) {
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
        return List.of(VulnerabilityReport.VulnerabilityType.PATH_TRAVERSAL);
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // Path traversal is most relevant for endpoints that might handle files
        // Look for file-related keywords in path or parameters
        String path = endpoint.getPath().toLowerCase();
        boolean hasFileKeywords = path.contains("file") ||
                                  path.contains("document") ||
                                  path.contains("download") ||
                                  path.contains("upload") ||
                                  path.contains("image") ||
                                  path.contains("attachment") ||
                                  path.contains("resource");

        // Also applicable to any GET endpoint with parameters
        boolean hasParameters = !endpoint.getQueryParameters().isEmpty() ||
                               !endpoint.getPathParameters().isEmpty();

        return hasFileKeywords || (endpoint.getMethod().equals("GET") && hasParameters);
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int totalTests = 0;

        logger.info("Starting Path Traversal scan on: " + endpoint);

        // Test query parameters
        TraversalTestResult queryResult = testQueryParameters(endpoint, httpClient, context);
        totalTests += queryResult.testsExecuted();
        if (queryResult.vulnerability().isPresent()) {
            vulnerabilities.add(queryResult.vulnerability().get());
        }

        // Test path parameters
        if (vulnerabilities.isEmpty()) {
            TraversalTestResult pathResult = testPathParameters(endpoint, httpClient, context);
            totalTests += pathResult.testsExecuted();
            if (pathResult.vulnerability().isPresent()) {
                vulnerabilities.add(pathResult.vulnerability().get());
            }
        }

        // Test body parameters
        if (vulnerabilities.isEmpty() && hasRequestBody(endpoint)) {
            TraversalTestResult bodyResult = testBodyParameters(endpoint, httpClient, context);
            totalTests += bodyResult.testsExecuted();
            if (bodyResult.vulnerability().isPresent()) {
                vulnerabilities.add(bodyResult.vulnerability().get());
            }
        }

        return createSuccessResult(endpoint, vulnerabilities, totalTests, startTime);
    }

    /**
     * Test query parameters for path traversal.
     */
    private TraversalTestResult testQueryParameters(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing query parameters for path traversal: " + endpoint);

        int testsExecuted = 0;

        for (ParameterSpec param : endpoint.getQueryParameters()) {
            // Focus on parameters that likely contain file paths
            if (isFileRelatedParameter(param.getName())) {
                for (TraversalPayload payload : TRAVERSAL_PAYLOADS) {
                    TestRequest request = createRequestWithParameter(
                        endpoint,
                        context,
                        param.getName(),
                        payload.path(),
                        ParameterLocation.QUERY
                    );

                    TestResponse response = executeTest(httpClient, request,
                        "Path traversal: " + param.getName() + " -> " + payload.description());
                    testsExecuted++;

                    if (containsFileContent(response)) {
                        return new TraversalTestResult(
                            Optional.of(createVulnerability(endpoint, param.getName(), payload, request, response, "query parameter")),
                            testsExecuted
                        );
                    }
                }
            }
        }

        return new TraversalTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Test path parameters for path traversal.
     */
    private TraversalTestResult testPathParameters(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing path parameters for path traversal: " + endpoint);

        int testsExecuted = 0;

        for (ParameterSpec param : endpoint.getPathParameters()) {
            for (TraversalPayload payload : TRAVERSAL_PAYLOADS) {
                TestRequest request = createRequestWithParameter(
                    endpoint,
                    context,
                    param.getName(),
                    payload.path(),
                    ParameterLocation.PATH
                );

                TestResponse response = executeTest(httpClient, request,
                    "Path traversal: " + param.getName() + " -> " + payload.description());
                testsExecuted++;

                if (containsFileContent(response)) {
                    return new TraversalTestResult(
                        Optional.of(createVulnerability(endpoint, param.getName(), payload, request, response, "path parameter")),
                        testsExecuted
                    );
                }
            }
        }

        return new TraversalTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Test body parameters for path traversal.
     */
    private TraversalTestResult testBodyParameters(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing body parameters for path traversal: " + endpoint);

        int testsExecuted = 0;

        try {
            Object schemaObj = endpoint.getMetadata().get("requestBodySchema");
            if (schemaObj == null) {
                return new TraversalTestResult(Optional.empty(), testsExecuted);
            }

            List<String> fieldNames = extractFieldNamesFromSchema(schemaObj);
            for (String fieldName : fieldNames) {
                if (isFileRelatedParameter(fieldName)) {
                    for (TraversalPayload payload : TRAVERSAL_PAYLOADS) {
                        TestRequest request = createRequestWithBodyParameter(
                            endpoint,
                            context,
                            fieldName,
                            payload.path()
                        );

                        TestResponse response = executeTest(httpClient, request,
                            "Body path traversal: " + fieldName);
                        testsExecuted++;

                        if (containsFileContent(response)) {
                            return new TraversalTestResult(
                                Optional.of(createVulnerability(endpoint, fieldName, payload, request, response, "body parameter")),
                                testsExecuted
                            );
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.warning("Failed to test body parameters: " + e.getMessage());
        }

        return new TraversalTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Check if parameter name suggests it might contain a file path.
     */
    private boolean isFileRelatedParameter(String paramName) {
        String lower = paramName.toLowerCase();
        return lower.contains("file") ||
               lower.contains("path") ||
               lower.contains("document") ||
               lower.contains("download") ||
               lower.contains("image") ||
               lower.contains("resource") ||
               lower.contains("attachment") ||
               lower.contains("template") ||
               lower.contains("page") ||
               lower.contains("url") ||
               lower.contains("location");
    }

    /**
     * Check if response contains sensitive file content.
     */
    private boolean containsFileContent(TestResponse response) {
        if (response.getStatusCode() != 200) {
            return false;
        }

        String body = response.getBody();
        if (body == null || body.isEmpty()) {
            return false;
        }

        return FILE_CONTENT_PATTERNS.stream()
            .anyMatch(pattern -> pattern.matcher(body).find());
    }

    private boolean hasRequestBody(ApiEndpoint endpoint) {
        String method = endpoint.getMethod();
        return (method.equals("POST") || method.equals("PUT") || method.equals("PATCH")) &&
               endpoint.getMetadata().get("requestBodySchema") != null;
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

            String jsonBody = objectMapper.writeValueAsString(bodyJson);
            return TestRequest.builder()
                .url(context.buildUrl(endpoint.getPath()))
                .method(endpoint.getMethod())
                .headers(context.getAuthHeaders())
                .addHeader("Content-Type", "application/json")
                .body(jsonBody)
                .build();
        } catch (Exception e) {
            logger.warning("Failed to create body parameter request: " + e.getMessage());
            return TestRequest.builder()
                .url(context.buildUrl(endpoint.getPath()))
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

    private VulnerabilityReport createVulnerability(
        ApiEndpoint endpoint,
        String paramName,
        TraversalPayload payload,
        TestRequest request,
        TestResponse response,
        String paramType
    ) {
        return VulnerabilityReport.builder()
            .type(VulnerabilityReport.VulnerabilityType.PATH_TRAVERSAL)
            .severity(Severity.HIGH)
            .endpoint(endpoint)
            .title("Path Traversal - " + payload.description())
            .description(
                "The endpoint is vulnerable to Path Traversal (Directory Traversal). " +
                "The application allows access to files outside the intended directory by manipulating " +
                "the '" + paramName + "' " + paramType + ". Successfully accessed sensitive file: " +
                payload.targetFile() + " using traversal payload: " + payload.path()
            )
            .exploitRequest(request)
            .exploitResponse(response)
            .addEvidence("parameter", paramName)
            .addEvidence("parameterType", paramType)
            .addEvidence("payload", payload.path())
            .addEvidence("targetFile", payload.targetFile())
            .addEvidence("statusCode", response.getStatusCode())
            .addRecommendation("Never use user input directly in file system operations")
            .addRecommendation("Use a whitelist of allowed files/directories")
            .addRecommendation("Validate and sanitize all file path inputs")
            .addRecommendation("Use absolute paths and resolve symbolic links")
            .addRecommendation("Implement proper access controls and chroot jails")
            .addRecommendation("Avoid exposing file system structure to users")
            .reproductionSteps(
                "1. Send " + endpoint.getMethod() + " request to " + request.getUrl() + "\n" +
                "2. Set " + paramType + " '" + paramName + "' to: " + payload.path() + "\n" +
                "3. Observe sensitive file content in response (target: " + payload.targetFile() + ")"
            )
            .build();
    }

    private enum ParameterLocation {
        QUERY, PATH, BODY, HEADER
    }

    private record TraversalPayload(String path, String targetFile, String description) {}

    private record TraversalTestResult(
        Optional<VulnerabilityReport> vulnerability,
        int testsExecuted
    ) {}
}
