package active.scanner.bopla;

import active.http.HttpClient;
import active.model.ApiEndpoint;
import active.model.TestRequest;
import active.model.TestResponse;
import active.model.VulnerabilityReport;
import active.scanner.AbstractScanner;
import active.scanner.ScanContext;
import active.scanner.ScanResult;
import active.scanner.ScannerConfig;
import model.Severity;

import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Scanner for detecting Broken Object Property Level Authorization vulnerabilities.
 *
 * <p>Broken Object Property Level Authorization occurs when an API endpoint does not
 * properly enforce authorization at the object property level, leading to:
 * <ul>
 *   <li>Exposure of sensitive properties that should be hidden (e.g., passwords, SSN)</li>
 *   <li>Excessive data exposure (returning more fields than necessary)</li>
 *   <li>Unauthorized modification of object properties (mass assignment)</li>
 *   <li>Lack of property-level access control based on user roles</li>
 * </ul>
 *
 * <p>Based on OWASP API Security Top 10 - API3:2023
 */
public final class BrokenObjectPropertyAuthScanner extends AbstractScanner {
    private static final String SCANNER_ID = "broken-object-property-auth-scanner";
    private static final String SCANNER_NAME = "Broken Object Property Level Authorization Scanner";
    private static final String SCANNER_DESCRIPTION =
        "Detects excessive data exposure, sensitive property leakage, and mass assignment vulnerabilities";

    // Patterns for sensitive property names
    private static final Set<String> SENSITIVE_PROPERTY_NAMES = Set.of(
        "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
        "private_key", "privatekey", "secret_key", "secretkey",
        "ssn", "social_security", "credit_card", "creditcard", "cvv", "cvc",
        "pin", "security_code", "bank_account", "routing_number",
        "tax_id", "driver_license", "passport", "salary", "medical_record",
        "authorization", "auth_token", "session", "cookie"
    );

    // Patterns for sensitive data in values
    private static final List<Pattern> SENSITIVE_DATA_PATTERNS = List.of(
        Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b"),  // SSN format
        Pattern.compile("\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"),  // Credit card
        Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"),  // Email (can be sensitive)
        Pattern.compile("\\$2[aby]\\$\\d+\\$[./A-Za-z0-9]{53}"),  // bcrypt hash
        Pattern.compile("sk_live_[0-9a-zA-Z]{24,}"),  // Stripe secret key
        Pattern.compile("-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")  // Private key
    );

    // Properties that often indicate excessive exposure
    private static final Set<String> INTERNAL_PROPERTY_NAMES = Set.of(
        "created_by", "updated_by", "internal_id", "internal_status",
        "debug", "trace", "stack_trace", "error_details",
        "database_id", "db_id", "raw_sql", "query"
    );

    public BrokenObjectPropertyAuthScanner() {
        super();
    }

    public BrokenObjectPropertyAuthScanner(ScannerConfig config) {
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
        return List.of(
            VulnerabilityReport.VulnerabilityType.BOPLA,
            VulnerabilityReport.VulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
            VulnerabilityReport.VulnerabilityType.MASS_ASSIGNMENT
        );
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // This scanner is primarily applicable to:
        // 1. GET endpoints that return object data
        // 2. POST/PUT/PATCH endpoints that accept object updates
        // 3. Endpoints that deal with user data or sensitive resources

        String method = endpoint.getMethod();
        String path = endpoint.getPath().toLowerCase();

        // Skip non-data endpoints
        if (path.contains("/health") ||
            path.contains("/status") ||
            path.contains("/ping") ||
            path.equals("/") ||
            path.equals("/api")) {
            return false;
        }

        // Applicable to endpoints that handle objects
        return method.equals("GET") ||
               method.equals("POST") ||
               method.equals("PUT") ||
               method.equals("PATCH");
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int totalTests = 0;

        // Test Case 1: Check for sensitive property exposure in GET responses
        if (endpoint.getMethod().equals("GET")) {
            PropertyTestResult sensitiveExposureTest = testSensitivePropertyExposure(
                endpoint, httpClient, context
            );
            totalTests += sensitiveExposureTest.testsExecuted();
            sensitiveExposureTest.vulnerability().ifPresent(vulnerabilities::add);

            // Test Case 2: Check for excessive data exposure
            PropertyTestResult excessiveDataTest = testExcessiveDataExposure(
                endpoint, httpClient, context
            );
            totalTests += excessiveDataTest.testsExecuted();
            excessiveDataTest.vulnerability().ifPresent(vulnerabilities::add);
        }

        // Test Case 3: Check for mass assignment vulnerabilities (POST/PUT/PATCH)
        if (endpoint.getMethod().equals("POST") ||
            endpoint.getMethod().equals("PUT") ||
            endpoint.getMethod().equals("PATCH")) {
            PropertyTestResult massAssignmentTest = testMassAssignment(
                endpoint, httpClient, context
            );
            totalTests += massAssignmentTest.testsExecuted();
            massAssignmentTest.vulnerability().ifPresent(vulnerabilities::add);
        }

        // Test Case 4: Check for role-based property access (if auth is available)
        if (context.getAuthHeaders() != null && !context.getAuthHeaders().isEmpty()) {
            PropertyTestResult roleBasedTest = testRoleBasedPropertyAccess(
                endpoint, httpClient, context
            );
            totalTests += roleBasedTest.testsExecuted();
            roleBasedTest.vulnerability().ifPresent(vulnerabilities::add);
        }

        return createSuccessResult(endpoint, vulnerabilities, totalTests, startTime);
    }

    /**
     * Test if endpoint exposes sensitive properties in the response.
     */
    private PropertyTestResult testSensitivePropertyExposure(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing sensitive property exposure for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        // Make authenticated request if auth is available
        TestRequest.Builder requestBuilder = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod());

        if (context.getAuthHeaders() != null) {
            requestBuilder.headers(context.getAuthHeaders());
        }

        TestRequest request = requestBuilder.build();
        TestResponse response = executeTest(httpClient, request, "Sensitive Property Exposure");

        // Analyze response for sensitive properties
        if (response.getStatusCode() >= 200 && response.getStatusCode() < 300) {
            Set<String> foundSensitiveProps = findSensitiveProperties(response.getBody());
            Set<String> foundSensitiveData = findSensitiveDataPatterns(response.getBody());

            if (!foundSensitiveProps.isEmpty() || !foundSensitiveData.isEmpty()) {
                StringBuilder description = new StringBuilder();
                description.append("The endpoint exposes sensitive properties in the response. ");

                if (!foundSensitiveProps.isEmpty()) {
                    description.append("Found sensitive property names: ")
                        .append(String.join(", ", foundSensitiveProps))
                        .append(". ");
                }

                if (!foundSensitiveData.isEmpty()) {
                    description.append("Detected sensitive data patterns: ")
                        .append(String.join(", ", foundSensitiveData))
                        .append(". ");
                }

                description.append("Sensitive properties should be filtered based on user roles and access levels.");

                VulnerabilityReport.Builder vulnBuilder = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.BOPLA)
                    .severity(Severity.HIGH)
                    .endpoint(endpoint)
                    .title("Sensitive Property Exposure")
                    .description(description.toString())
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("statusCode", response.getStatusCode())
                    .addRecommendation("Implement property-level access control based on user roles")
                    .addRecommendation("Use DTOs/serialization groups to control exposed fields")
                    .addRecommendation("Never expose sensitive fields like passwords, tokens, or PII")
                    .addRecommendation("Apply the principle of least privilege for data access")
                    .reproductionSteps(
                        "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                        "2. Examine response body for sensitive properties\n" +
                        "3. Observe exposure of: " + String.join(", ", foundSensitiveProps)
                    );

                if (!foundSensitiveProps.isEmpty()) {
                    vulnBuilder.addEvidence("sensitiveProperties", new ArrayList<>(foundSensitiveProps));
                }
                if (!foundSensitiveData.isEmpty()) {
                    vulnBuilder.addEvidence("sensitiveDataPatterns", new ArrayList<>(foundSensitiveData));
                }

                return new PropertyTestResult(Optional.of(vulnBuilder.build()), 1);
            }
        }

        return new PropertyTestResult(Optional.empty(), 1);
    }

    /**
     * Test if endpoint returns excessive data (internal fields, debug info).
     */
    private PropertyTestResult testExcessiveDataExposure(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing excessive data exposure for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest.Builder requestBuilder = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod());

        if (context.getAuthHeaders() != null) {
            requestBuilder.headers(context.getAuthHeaders());
        }

        TestRequest request = requestBuilder.build();
        TestResponse response = executeTest(httpClient, request, "Excessive Data Exposure");

        if (response.getStatusCode() >= 200 && response.getStatusCode() < 300) {
            Set<String> foundInternalProps = findInternalProperties(response.getBody());
            int propertyCount = countProperties(response.getBody());

            // Flag if we find internal properties or an excessive number of fields
            if (!foundInternalProps.isEmpty() || propertyCount > 50) {
                StringBuilder description = new StringBuilder();
                description.append("The endpoint exposes excessive or internal data. ");

                if (!foundInternalProps.isEmpty()) {
                    description.append("Found internal properties: ")
                        .append(String.join(", ", foundInternalProps))
                        .append(". ");
                }

                if (propertyCount > 50) {
                    description.append("Response contains ").append(propertyCount)
                        .append(" properties, which may indicate over-exposure. ");
                }

                description.append("APIs should only return data necessary for the client's use case.");

                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.EXCESSIVE_DATA_EXPOSURE)
                    .severity(Severity.MEDIUM)
                    .endpoint(endpoint)
                    .title("Excessive Data Exposure")
                    .description(description.toString())
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("statusCode", response.getStatusCode())
                    .addEvidence("propertyCount", propertyCount)
                    .addEvidence("internalProperties", new ArrayList<>(foundInternalProps))
                    .addRecommendation("Return only the fields needed for the specific use case")
                    .addRecommendation("Use DTOs to define explicit API contracts")
                    .addRecommendation("Remove internal/debug fields from production responses")
                    .addRecommendation("Implement field filtering (e.g., sparse fieldsets, GraphQL)")
                    .reproductionSteps(
                        "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                        "2. Examine response body for excessive fields\n" +
                        "3. Count exposed properties: " + propertyCount
                    )
                    .build();

                return new PropertyTestResult(Optional.of(vulnerability), 1);
            }
        }

        return new PropertyTestResult(Optional.empty(), 1);
    }

    /**
     * Test for mass assignment vulnerabilities by attempting to modify protected fields.
     */
    private PropertyTestResult testMassAssignment(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing mass assignment for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        // List of protected fields that should not be user-modifiable
        List<String> protectedFields = List.of(
            "is_admin", "isAdmin", "admin", "role", "roles",
            "is_verified", "isVerified", "verified",
            "balance", "credit", "points", "score",
            "id", "_id", "user_id", "userId"
        );

        // Try to inject protected fields
        Map<String, Object> maliciousPayload = new HashMap<>();
        maliciousPayload.put("is_admin", true);
        maliciousPayload.put("role", "admin");
        maliciousPayload.put("balance", 9999999);
        maliciousPayload.put("verified", true);

        TestRequest.Builder requestBuilder = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .body(payloadToJson(maliciousPayload))
            .addHeader("Content-Type", "application/json");

        if (context.getAuthHeaders() != null) {
            context.getAuthHeaders().forEach(requestBuilder::addHeader);
        }

        TestRequest request = requestBuilder.build();
        TestResponse response = executeTest(httpClient, request, "Mass Assignment");

        // If the request succeeds without error, it might be vulnerable
        if (response.getStatusCode() >= 200 && response.getStatusCode() < 300) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.MASS_ASSIGNMENT)
                .severity(Severity.HIGH)
                .endpoint(endpoint)
                .title("Potential Mass Assignment Vulnerability")
                .description(
                    "The endpoint accepts a request with protected field assignments without proper validation. " +
                    "Attempted to set protected fields (is_admin, role, balance, verified) and received " +
                    response.getStatusCode() + " status. " +
                    "This could allow attackers to modify properties they shouldn't have access to."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("statusCode", response.getStatusCode())
                .addEvidence("attemptedFields", protectedFields)
                .addRecommendation("Use allowlists (not blocklists) for accepting user input properties")
                .addRecommendation("Define explicit DTOs with only modifiable fields")
                .addRecommendation("Validate that sensitive fields cannot be modified by users")
                .addRecommendation("Implement proper authorization checks for property updates")
                .reproductionSteps(
                    "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                    "2. Include protected fields in request body: " + maliciousPayload + "\n" +
                    "3. Observe " + response.getStatusCode() + " response (should reject with 400/403)"
                )
                .build();

            return new PropertyTestResult(Optional.of(vulnerability), 1);
        }

        return new PropertyTestResult(Optional.empty(), 1);
    }

    /**
     * Test if property access is properly restricted based on user roles.
     */
    private PropertyTestResult testRoleBasedPropertyAccess(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing role-based property access for: " + endpoint);

        // This is a basic test - in a real scenario, you'd need multiple auth contexts
        // For now, we'll just make a baseline request and check for role-sensitive fields

        String url = context.buildUrl(endpoint.getPath());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Role-Based Access");

        if (response.getStatusCode() >= 200 && response.getStatusCode() < 300) {
            // Look for role-specific fields that might be exposed
            Set<String> roleFields = findRoleSpecificFields(response.getBody());

            if (!roleFields.isEmpty()) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.BOPLA)
                    .severity(Severity.MEDIUM)
                    .endpoint(endpoint)
                    .title("Potential Role-Based Property Access Issue")
                    .description(
                        "The endpoint returns properties that appear to be role-specific: " +
                        String.join(", ", roleFields) + ". " +
                        "Verify that these properties are only accessible to authorized roles."
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("statusCode", response.getStatusCode())
                    .addEvidence("roleSpecificFields", new ArrayList<>(roleFields))
                    .addRecommendation("Implement property-level authorization based on user roles")
                    .addRecommendation("Use different serialization views for different user roles")
                    .addRecommendation("Verify authorization for each sensitive property access")
                    .reproductionSteps(
                        "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                        "2. Authenticate with different user roles\n" +
                        "3. Verify that role-specific fields are properly restricted"
                    )
                    .build();

                return new PropertyTestResult(Optional.of(vulnerability), 1);
            }
        }

        return new PropertyTestResult(Optional.empty(), 1);
    }

    /**
     * Find sensitive property names in response body.
     */
    private Set<String> findSensitiveProperties(String responseBody) {
        if (responseBody == null || responseBody.isEmpty()) {
            return Collections.emptySet();
        }

        Set<String> found = new HashSet<>();
        String lowerBody = responseBody.toLowerCase();

        for (String sensitiveProp : SENSITIVE_PROPERTY_NAMES) {
            if (lowerBody.contains("\"" + sensitiveProp + "\"") ||
                lowerBody.contains("'" + sensitiveProp + "'")) {
                found.add(sensitiveProp);
            }
        }

        return found;
    }

    /**
     * Find sensitive data patterns in response body.
     */
    private Set<String> findSensitiveDataPatterns(String responseBody) {
        if (responseBody == null || responseBody.isEmpty()) {
            return Collections.emptySet();
        }

        Set<String> found = new HashSet<>();

        for (Pattern pattern : SENSITIVE_DATA_PATTERNS) {
            if (pattern.matcher(responseBody).find()) {
                found.add(pattern.pattern().substring(0, Math.min(30, pattern.pattern().length())));
            }
        }

        return found;
    }

    /**
     * Find internal property names in response body.
     */
    private Set<String> findInternalProperties(String responseBody) {
        if (responseBody == null || responseBody.isEmpty()) {
            return Collections.emptySet();
        }

        Set<String> found = new HashSet<>();
        String lowerBody = responseBody.toLowerCase();

        for (String internalProp : INTERNAL_PROPERTY_NAMES) {
            if (lowerBody.contains("\"" + internalProp + "\"") ||
                lowerBody.contains("'" + internalProp + "'")) {
                found.add(internalProp);
            }
        }

        return found;
    }

    /**
     * Find role-specific fields in response body.
     */
    private Set<String> findRoleSpecificFields(String responseBody) {
        if (responseBody == null || responseBody.isEmpty()) {
            return Collections.emptySet();
        }

        Set<String> roleFields = Set.of("admin", "role", "roles", "permissions", "privileges", "is_admin");
        Set<String> found = new HashSet<>();
        String lowerBody = responseBody.toLowerCase();

        for (String roleField : roleFields) {
            if (lowerBody.contains("\"" + roleField + "\"") ||
                lowerBody.contains("'" + roleField + "'")) {
                found.add(roleField);
            }
        }

        return found;
    }

    /**
     * Count approximate number of properties in JSON response.
     */
    private int countProperties(String responseBody) {
        if (responseBody == null || responseBody.isEmpty()) {
            return 0;
        }

        // Simple heuristic: count quotes that are likely property names
        int count = 0;
        boolean inString = false;
        char prevChar = ' ';

        for (char c : responseBody.toCharArray()) {
            if (c == '"' && prevChar != '\\') {
                if (!inString) {
                    count++;
                }
                inString = !inString;
            }
            prevChar = c;
        }

        // Divide by 2 since each property has opening and closing quotes
        return count / 2;
    }

    /**
     * Convert payload map to JSON string (simple implementation).
     */
    private String payloadToJson(Map<String, Object> payload) {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;

        for (Map.Entry<String, Object> entry : payload.entrySet()) {
            if (!first) {
                json.append(",");
            }
            first = false;

            json.append("\"").append(entry.getKey()).append("\":");

            Object value = entry.getValue();
            if (value instanceof String) {
                json.append("\"").append(value).append("\"");
            } else if (value instanceof Boolean || value instanceof Number) {
                json.append(value);
            } else {
                json.append("\"").append(value).append("\"");
            }
        }

        json.append("}");
        return json.toString();
    }

    /**
     * Result of a property-level test case.
     */
    private record PropertyTestResult(
        Optional<VulnerabilityReport> vulnerability,
        int testsExecuted
    ) {}
}
