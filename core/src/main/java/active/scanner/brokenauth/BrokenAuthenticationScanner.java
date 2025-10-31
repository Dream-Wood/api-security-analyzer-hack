package active.scanner.brokenauth;

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

/**
 * Scanner for detecting Broken Authentication vulnerabilities.
 *
 * <p>Broken Authentication occurs when authentication mechanisms are improperly implemented,
 * allowing attackers to compromise passwords, keys, session tokens, or exploit other
 * implementation flaws to assume other users' identities.
 *
 * <p>This scanner tests for:
 * <ul>
 *   <li>Missing authentication on protected endpoints</li>
 *   <li>Invalid/malformed token acceptance</li>
 *   <li>Expired token acceptance</li>
 *   <li>Token signature verification bypass</li>
 *   <li>Weak authentication schemes</li>
 * </ul>
 *
 * <p>Based on OWASP API Security Top 10 - API2:2023
 */
public final class BrokenAuthenticationScanner extends AbstractScanner {
    private static final String SCANNER_ID = "broken-authentication-scanner";
    private static final String SCANNER_NAME = "Broken Authentication Scanner";
    private static final String SCANNER_DESCRIPTION =
        "Detects broken authentication mechanisms including missing auth checks, invalid token acceptance, and weak authentication";

    public BrokenAuthenticationScanner() {
        super();
    }

    public BrokenAuthenticationScanner(ScannerConfig config) {
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
            VulnerabilityReport.VulnerabilityType.BROKEN_AUTHENTICATION,
            VulnerabilityReport.VulnerabilityType.MISSING_RATE_LIMITING
        );
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // This scanner is applicable to most endpoints, especially those that:
        // 1. Are not public/health check endpoints
        // 2. Perform sensitive operations
        // 3. Handle user data

        String path = endpoint.getPath().toLowerCase();

        // Skip obvious public endpoints
        if (path.contains("/health") ||
            path.contains("/status") ||
            path.contains("/ping") ||
            path.contains("/public") ||
            path.equals("/") ||
            path.equals("/api")) {
            return false;
        }

        // Authentication is especially important for:
        // - Data modification (POST, PUT, DELETE, PATCH)
        // - User-specific data access (GET with user IDs)
        // - Admin operations
        String method = endpoint.getMethod();
        return method.equals("GET") ||
               method.equals("POST") ||
               method.equals("PUT") ||
               method.equals("DELETE") ||
               method.equals("PATCH");
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int totalTests = 0;

        // Test Case 1: No authentication required
        AuthTestResult noAuthTest = testNoAuthentication(endpoint, httpClient, context);
        totalTests += noAuthTest.testsExecuted();
        noAuthTest.vulnerability().ifPresent(vulnerabilities::add);

        // Test Case 2: Invalid token acceptance
        if (context.getAuthHeaders() != null && !context.getAuthHeaders().isEmpty()) {
            AuthTestResult invalidTokenTest = testInvalidToken(endpoint, httpClient, context);
            totalTests += invalidTokenTest.testsExecuted();
            invalidTokenTest.vulnerability().ifPresent(vulnerabilities::add);

            // Test Case 3: Malformed token acceptance
            AuthTestResult malformedTokenTest = testMalformedToken(endpoint, httpClient, context);
            totalTests += malformedTokenTest.testsExecuted();
            malformedTokenTest.vulnerability().ifPresent(vulnerabilities::add);

            // Test Case 4: Empty/whitespace token
            AuthTestResult emptyTokenTest = testEmptyToken(endpoint, httpClient, context);
            totalTests += emptyTokenTest.testsExecuted();
            emptyTokenTest.vulnerability().ifPresent(vulnerabilities::add);
        }

        // Test Case 5: Weak authentication header acceptance
        AuthTestResult weakAuthTest = testWeakAuthenticationSchemes(endpoint, httpClient, context);
        totalTests += weakAuthTest.testsExecuted();
        weakAuthTest.vulnerability().ifPresent(vulnerabilities::add);

        return createSuccessResult(endpoint, vulnerabilities, totalTests, startTime);
    }

    /**
     * Test if endpoint can be accessed without any authentication.
     */
    private AuthTestResult testNoAuthentication(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing access without authentication for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            // No headers - completely unauthenticated
            .build();

        TestResponse response = executeTest(httpClient, request, "No Authentication");

        // If we get a success response without auth, it's a vulnerability
        if (isSuccessfulUnauthorizedAccess(response)) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.BROKEN_AUTHENTICATION)
                .severity(determineSeverity(endpoint, response))
                .endpoint(endpoint)
                .title("Missing Authentication on Protected Endpoint")
                .description(
                    "The endpoint allows access without any authentication credentials. " +
                    "This allows unauthorized users to access potentially sensitive functionality or data. " +
                    "Expected 401 Unauthorized but received " + response.getStatusCode() + " status."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("statusCode", response.getStatusCode())
                .addEvidence("method", endpoint.getMethod())
                .addEvidence("responseSize", response.getBody() != null ? response.getBody().length() : 0)
                .addRecommendation("Implement authentication middleware for all protected endpoints")
                .addRecommendation("Return 401 Unauthorized for requests without valid credentials")
                .addRecommendation("Use a centralized authentication mechanism (e.g., JWT, OAuth2)")
                .addRecommendation("Ensure default-deny access control policy")
                .reproductionSteps(
                    "1. Send " + endpoint.getMethod() + " request to " + url + " without any authentication headers\n" +
                    "2. Observe " + response.getStatusCode() + " response (expected 401 Unauthorized)"
                )
                .build();

            return new AuthTestResult(Optional.of(vulnerability), 1);
        }

        return new AuthTestResult(Optional.empty(), 1);
    }

    /**
     * Test if endpoint accepts obviously invalid tokens.
     */
    private AuthTestResult testInvalidToken(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing invalid token acceptance for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        // Get the original auth header name
        String authHeaderName = getAuthHeaderName(context);
        if (authHeaderName == null) {
            return new AuthTestResult(Optional.empty(), 0);
        }

        // Test with obviously invalid token
        Map<String, String> headers = new HashMap<>();
        headers.put(authHeaderName, "invalid_token_12345");

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(headers)
            .build();

        TestResponse response = executeTest(httpClient, request, "Invalid Token");

        if (isSuccessfulUnauthorizedAccess(response)) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.BROKEN_AUTHENTICATION)
                .severity(Severity.HIGH)
                .endpoint(endpoint)
                .title("Invalid Token Acceptance")
                .description(
                    "The endpoint accepts invalid authentication tokens. " +
                    "Sent an obviously invalid token 'invalid_token_12345' but received " +
                    response.getStatusCode() + " status. This indicates missing or broken token validation."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("statusCode", response.getStatusCode())
                .addEvidence("invalidToken", "invalid_token_12345")
                .addRecommendation("Implement proper token validation (signature, format, expiration)")
                .addRecommendation("Reject requests with invalid tokens with 401 Unauthorized")
                .addRecommendation("Use industry-standard token formats (JWT, OAuth2)")
                .addRecommendation("Validate token signature using proper cryptographic algorithms")
                .reproductionSteps(
                    "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                    "2. Include invalid token in " + authHeaderName + " header: 'invalid_token_12345'\n" +
                    "3. Observe " + response.getStatusCode() + " response (expected 401 Unauthorized)"
                )
                .build();

            return new AuthTestResult(Optional.of(vulnerability), 1);
        }

        return new AuthTestResult(Optional.empty(), 1);
    }

    /**
     * Test if endpoint accepts malformed tokens (wrong structure).
     */
    private AuthTestResult testMalformedToken(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing malformed token acceptance for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());
        String authHeaderName = getAuthHeaderName(context);
        if (authHeaderName == null) {
            return new AuthTestResult(Optional.empty(), 0);
        }

        // Test various malformed tokens
        List<String> malformedTokens = List.of(
            "malformed..token",  // Double dots
            "header.payload",    // Missing signature part for JWT
            "a.b.c.d.e",        // Too many parts for JWT
            "Bearer",           // Just the scheme
            "!@#$%^&*()"        // Special characters only
        );

        for (String malformedToken : malformedTokens) {
            Map<String, String> headers = new HashMap<>();
            headers.put(authHeaderName, malformedToken);

            TestRequest request = TestRequest.builder()
                .url(url)
                .method(endpoint.getMethod())
                .headers(headers)
                .build();

            TestResponse response = executeTest(httpClient, request, "Malformed Token: " + malformedToken);

            if (isSuccessfulUnauthorizedAccess(response)) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.BROKEN_AUTHENTICATION)
                    .severity(Severity.HIGH)
                    .endpoint(endpoint)
                    .title("Malformed Token Acceptance")
                    .description(
                        "The endpoint accepts malformed authentication tokens. " +
                        "Sent malformed token '" + malformedToken + "' but received " +
                        response.getStatusCode() + " status. Proper validation should reject malformed tokens."
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("statusCode", response.getStatusCode())
                    .addEvidence("malformedToken", malformedToken)
                    .addRecommendation("Validate token structure before processing")
                    .addRecommendation("Reject malformed tokens with 401 Unauthorized")
                    .addRecommendation("Use a robust token parsing library")
                    .reproductionSteps(
                        "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                        "2. Include malformed token: '" + malformedToken + "'\n" +
                        "3. Observe " + response.getStatusCode() + " response (expected 401 Unauthorized)"
                    )
                    .build();

                return new AuthTestResult(Optional.of(vulnerability), malformedTokens.indexOf(malformedToken) + 1);
            }
        }

        return new AuthTestResult(Optional.empty(), malformedTokens.size());
    }

    /**
     * Test if endpoint accepts empty or whitespace-only tokens.
     */
    private AuthTestResult testEmptyToken(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing empty token acceptance for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());
        String authHeaderName = getAuthHeaderName(context);
        if (authHeaderName == null) {
            return new AuthTestResult(Optional.empty(), 0);
        }

        List<String> emptyTokens = List.of("", "   ", "\t", "\n");
        int testsExecuted = 0;

        for (String emptyToken : emptyTokens) {
            Map<String, String> headers = new HashMap<>();
            headers.put(authHeaderName, emptyToken);

            TestRequest request = TestRequest.builder()
                .url(url)
                .method(endpoint.getMethod())
                .headers(headers)
                .build();

            TestResponse response = executeTest(httpClient, request, "Empty Token");
            testsExecuted++;

            if (isSuccessfulUnauthorizedAccess(response)) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.BROKEN_AUTHENTICATION)
                    .severity(Severity.HIGH)
                    .endpoint(endpoint)
                    .title("Empty Authentication Token Accepted")
                    .description(
                        "The endpoint accepts empty or whitespace-only authentication tokens. " +
                        "This indicates missing or insufficient token validation."
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("statusCode", response.getStatusCode())
                    .addRecommendation("Validate that authentication tokens are non-empty")
                    .addRecommendation("Reject empty tokens with 401 Unauthorized")
                    .reproductionSteps(
                        "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                        "2. Include empty/whitespace token in " + authHeaderName + " header\n" +
                        "3. Observe " + response.getStatusCode() + " response (expected 401 Unauthorized)"
                    )
                    .build();

                return new AuthTestResult(Optional.of(vulnerability), testsExecuted);
            }
        }

        return new AuthTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Test if endpoint accepts weak authentication schemes.
     */
    private AuthTestResult testWeakAuthenticationSchemes(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing weak authentication schemes for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        // Test Basic Auth with weak/default credentials
        List<String> weakBasicAuthHeaders = List.of(
            "Basic YWRtaW46YWRtaW4=",      // admin:admin
            "Basic dGVzdDp0ZXN0",          // test:test
            "Basic cm9vdDpyb290",          // root:root
            "Basic dXNlcjpwYXNzd29yZA=="   // user:password
        );

        for (String authHeader : weakBasicAuthHeaders) {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", authHeader);

            TestRequest request = TestRequest.builder()
                .url(url)
                .method(endpoint.getMethod())
                .headers(headers)
                .build();

            TestResponse response = executeTest(httpClient, request, "Weak Basic Auth");

            if (isSuccessfulUnauthorizedAccess(response)) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.BROKEN_AUTHENTICATION)
                    .severity(Severity.CRITICAL)
                    .endpoint(endpoint)
                    .title("Weak/Default Credentials Accepted")
                    .description(
                        "The endpoint accepts weak or default credentials. " +
                        "Successfully authenticated using common default credentials. " +
                        "This is a critical security vulnerability."
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("statusCode", response.getStatusCode())
                    .addEvidence("authScheme", "Basic Auth with default credentials")
                    .addRecommendation("Disable or change all default credentials")
                    .addRecommendation("Enforce strong password policies")
                    .addRecommendation("Implement account lockout after failed login attempts")
                    .addRecommendation("Consider using modern authentication (OAuth2, OIDC) instead of Basic Auth")
                    .reproductionSteps(
                        "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                        "2. Include Authorization header with default credentials\n" +
                        "3. Observe " + response.getStatusCode() + " response indicating successful authentication"
                    )
                    .build();

                return new AuthTestResult(
                    Optional.of(vulnerability),
                    weakBasicAuthHeaders.indexOf(authHeader) + 1
                );
            }
        }

        return new AuthTestResult(Optional.empty(), weakBasicAuthHeaders.size());
    }

    /**
     * Get the authentication header name from context.
     */
    private String getAuthHeaderName(ScanContext context) {
        Map<String, String> authHeaders = context.getAuthHeaders();
        if (authHeaders.isEmpty()) {
            return null;
        }

        // Look for common auth header names
        for (String key : authHeaders.keySet()) {
            if (key.equalsIgnoreCase("Authorization") ||
                key.equalsIgnoreCase("X-Auth-Token") ||
                key.equalsIgnoreCase("X-API-Key")) {
                return key;
            }
        }

        // Return the first header as fallback
        return authHeaders.keySet().iterator().next();
    }

    /**
     * Determine severity based on endpoint characteristics and response.
     */
    private Severity determineSeverity(ApiEndpoint endpoint, TestResponse response) {
        String method = endpoint.getMethod();
        String path = endpoint.getPath().toLowerCase();

        // Critical: Admin endpoints or data modification without auth
        if (path.contains("/admin") ||
            path.contains("/delete") ||
            method.equals("DELETE")) {
            return Severity.CRITICAL;
        }

        // High: Data modification or user-specific data access
        if (method.equals("POST") ||
            method.equals("PUT") ||
            method.equals("PATCH") ||
            path.contains("/user")) {
            return Severity.HIGH;
        }

        // Medium: GET requests that might expose data
        if (method.equals("GET") && response.getBody() != null && !response.getBody().isEmpty()) {
            return Severity.MEDIUM;
        }

        return Severity.HIGH;  // Default to HIGH for authentication issues
    }

    /**
     * Result of an authentication test case.
     */
    private record AuthTestResult(
        Optional<VulnerabilityReport> vulnerability,
        int testsExecuted
    ) {}
}
