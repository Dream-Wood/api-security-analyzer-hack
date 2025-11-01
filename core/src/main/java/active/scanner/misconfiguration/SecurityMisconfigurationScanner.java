package active.scanner.misconfiguration;

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
 * Scanner for detecting Security Misconfiguration vulnerabilities.
 *
 * <p>Security Misconfiguration occurs when security settings are not properly
 * implemented, leaving the API vulnerable to attacks. This is one of the most
 * common issues in APIs due to complex configurations and defaults.
 *
 * <p>This scanner tests for:
 * <ul>
 *   <li>Missing security headers (HSTS, X-Frame-Options, CSP, etc.)</li>
 *   <li>Information disclosure (server version, stack traces)</li>
 *   <li>CORS misconfiguration (permissive origins)</li>
 *   <li>Unnecessary HTTP methods enabled</li>
 *   <li>Verbose error messages</li>
 *   <li>Insecure cookie attributes</li>
 *   <li>Missing cache control on sensitive endpoints</li>
 * </ul>
 *
 * <p>Based on OWASP API Security Top 10 - API8:2023
 */
public final class SecurityMisconfigurationScanner extends AbstractScanner {
    private static final String SCANNER_ID = "security-misconfiguration-scanner";
    private static final String SCANNER_NAME = "Security Misconfiguration Scanner";
    private static final String SCANNER_DESCRIPTION =
        "Detects security misconfigurations including missing headers, CORS issues, and information disclosure";

    // Critical security headers that should be present
    private static final List<String> REQUIRED_SECURITY_HEADERS = List.of(
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy"
    );

    // Headers that leak information
    private static final List<String> INFORMATION_DISCLOSURE_HEADERS = List.of(
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Runtime"
    );

    // Potentially dangerous HTTP methods
    private static final List<String> DANGEROUS_METHODS = List.of(
        "TRACE",
        "TRACK",
        "CONNECT"
    );

    // Patterns indicating verbose error messages
    private static final List<String> ERROR_PATTERNS = List.of(
        "Exception",
        "Stack trace",
        "at com.",
        "at java.",
        "at org.",
        "at net.",
        "SQLException",
        "NullPointerException",
        "ArrayIndexOutOfBoundsException",
        "FileNotFoundException",
        "stacktrace",
        "Traceback",
        "line \\d+",
        "/usr/",
        "/var/",
        "C:\\\\",
        "Database error"
    );

    public SecurityMisconfigurationScanner() {
        super();
    }

    public SecurityMisconfigurationScanner(ScannerConfig config) {
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
        return List.of(VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION);
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // This scanner is applicable to all endpoints
        // We want to check security headers and configuration on every endpoint
        return true;
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int totalTests = 0;

        // Test Case 1: Missing security headers
        MisconfigTestResult headersTest = testSecurityHeaders(endpoint, httpClient, context);
        totalTests += headersTest.testsExecuted();
        vulnerabilities.addAll(headersTest.vulnerabilities());

        // Test Case 2: Information disclosure
        MisconfigTestResult infoDisclosureTest = testInformationDisclosure(endpoint, httpClient, context);
        totalTests += infoDisclosureTest.testsExecuted();
        vulnerabilities.addAll(infoDisclosureTest.vulnerabilities());

        // Test Case 3: CORS misconfiguration
        MisconfigTestResult corsTest = testCorsMisconfiguration(endpoint, httpClient, context);
        totalTests += corsTest.testsExecuted();
        vulnerabilities.addAll(corsTest.vulnerabilities());

        // Test Case 4: Dangerous HTTP methods
        MisconfigTestResult methodsTest = testDangerousMethods(endpoint, httpClient, context);
        totalTests += methodsTest.testsExecuted();
        vulnerabilities.addAll(methodsTest.vulnerabilities());

        // Test Case 5: Verbose error messages
        MisconfigTestResult errorTest = testVerboseErrors(endpoint, httpClient, context);
        totalTests += errorTest.testsExecuted();
        vulnerabilities.addAll(errorTest.vulnerabilities());

        // Test Case 6: Cache control on sensitive endpoints
        if (isSensitiveEndpoint(endpoint)) {
            MisconfigTestResult cacheTest = testCacheControl(endpoint, httpClient, context);
            totalTests += cacheTest.testsExecuted();
            vulnerabilities.addAll(cacheTest.vulnerabilities());
        }

        return createSuccessResult(endpoint, vulnerabilities, totalTests, startTime);
    }

    /**
     * Test for missing security headers.
     */
    private MisconfigTestResult testSecurityHeaders(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing security headers for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Security Headers Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        List<String> missingHeaders = new ArrayList<>();

        // Check for required security headers
        for (String requiredHeader : REQUIRED_SECURITY_HEADERS) {
            if (!hasHeader(response, requiredHeader)) {
                missingHeaders.add(requiredHeader);
            }
        }

        if (!missingHeaders.isEmpty()) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.MEDIUM)
                .endpoint(endpoint)
                .title("Missing Security Headers")
                .description(
                    "The API response is missing important security headers. " +
                    "Missing headers: " + String.join(", ", missingHeaders) + ". " +
                    "These headers provide additional security layers by instructing browsers " +
                    "on how to handle content, preventing various attacks like clickjacking, " +
                    "XSS, and ensuring HTTPS is used."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("missingHeaders", missingHeaders)
                .addEvidence("statusCode", response.getStatusCode())
                .addRecommendation("Add Strict-Transport-Security: max-age=31536000; includeSubDomains")
                .addRecommendation("Add X-Content-Type-Options: nosniff")
                .addRecommendation("Add X-Frame-Options: DENY or SAMEORIGIN")
                .addRecommendation("Add Content-Security-Policy with appropriate directives")
                .addRecommendation("Review and implement all OWASP recommended security headers")
                .reproductionSteps(
                    "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                    "2. Examine response headers\n" +
                    "3. Notice missing security headers: " + String.join(", ", missingHeaders)
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        return new MisconfigTestResult(vulnerabilities, 1);
    }

    /**
     * Test for information disclosure in headers.
     */
    private MisconfigTestResult testInformationDisclosure(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing information disclosure for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Information Disclosure Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        Map<String, String> disclosedInfo = new HashMap<>();

        // Check for information disclosure headers
        for (String header : INFORMATION_DISCLOSURE_HEADERS) {
            String value = getHeader(response, header);
            if (value != null && !value.isEmpty()) {
                disclosedInfo.put(header, value);
            }
        }

        if (!disclosedInfo.isEmpty()) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.LOW)
                .endpoint(endpoint)
                .title("Information Disclosure via HTTP Headers")
                .description(
                    "The API exposes technical implementation details through HTTP headers. " +
                    "Disclosed information: " + disclosedInfo + ". " +
                    "This information can help attackers identify specific versions and technologies " +
                    "to target known vulnerabilities."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("disclosedHeaders", disclosedInfo)
                .addRecommendation("Remove or obfuscate Server header")
                .addRecommendation("Remove X-Powered-By and similar technology headers")
                .addRecommendation("Configure web server to suppress version information")
                .addRecommendation("Use generic error messages without technical details")
                .reproductionSteps(
                    "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                    "2. Examine response headers\n" +
                    "3. Observe technical details: " + disclosedInfo
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        return new MisconfigTestResult(vulnerabilities, 1);
    }

    /**
     * Test for CORS misconfiguration.
     */
    private MisconfigTestResult testCorsMisconfiguration(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing CORS configuration for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        // Test with malicious origin
        Map<String, String> corsHeaders = new HashMap<>(context.getAuthHeaders());
        corsHeaders.put("Origin", "https://evil.com");

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(corsHeaders)
            .build();

        TestResponse response = executeTest(httpClient, request, "CORS Configuration Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();

        String allowOrigin = getHeader(response, "Access-Control-Allow-Origin");
        String allowCredentials = getHeader(response, "Access-Control-Allow-Credentials");

        // Check for permissive CORS
        if ("*".equals(allowOrigin)) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.MEDIUM)
                .endpoint(endpoint)
                .title("Permissive CORS Configuration")
                .description(
                    "The API uses a wildcard (*) in Access-Control-Allow-Origin header, " +
                    "allowing any website to make cross-origin requests. This can expose " +
                    "sensitive data to malicious websites and enable CSRF attacks."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("Access-Control-Allow-Origin", "*")
                .addRecommendation("Use specific origins instead of wildcard")
                .addRecommendation("Validate and whitelist allowed origins")
                .addRecommendation("Avoid wildcard with credentials")
                .addRecommendation("Implement proper CSRF protection")
                .reproductionSteps(
                    "1. Send request with Origin: https://evil.com\n" +
                    "2. Observe Access-Control-Allow-Origin: *\n" +
                    "3. Any malicious site can make cross-origin requests"
                )
                .build();

            vulnerabilities.add(vulnerability);
        } else if ("https://evil.com".equals(allowOrigin)) {
            // Origin reflection - even worse
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.HIGH)
                .endpoint(endpoint)
                .title("CORS Origin Reflection Vulnerability")
                .description(
                    "The API reflects the Origin header in Access-Control-Allow-Origin without validation. " +
                    "This allows any attacker-controlled domain to make authenticated cross-origin requests, " +
                    "potentially exposing sensitive data and enabling sophisticated attacks."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("Origin", "https://evil.com")
                .addEvidence("Access-Control-Allow-Origin", allowOrigin)
                .addRecommendation("Implement strict origin validation")
                .addRecommendation("Maintain a whitelist of allowed origins")
                .addRecommendation("Never reflect Origin header without validation")
                .reproductionSteps(
                    "1. Send request with Origin: https://evil.com\n" +
                    "2. Observe Access-Control-Allow-Origin: https://evil.com\n" +
                    "3. Attacker can make authenticated requests from any domain"
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        // Check for credentials with wildcard (critical issue)
        if ("*".equals(allowOrigin) && "true".equalsIgnoreCase(allowCredentials)) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.CRITICAL)
                .endpoint(endpoint)
                .title("Critical CORS Misconfiguration: Credentials with Wildcard")
                .description(
                    "The API allows credentials (Access-Control-Allow-Credentials: true) " +
                    "with wildcard origin (*). This is a critical security issue that can " +
                    "expose user sessions and authentication tokens to any malicious website."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("Access-Control-Allow-Origin", "*")
                .addEvidence("Access-Control-Allow-Credentials", "true")
                .addRecommendation("NEVER use wildcard origin with credentials")
                .addRecommendation("Use specific origins when credentials are needed")
                .addRecommendation("Implement proper CSRF tokens")
                .reproductionSteps(
                    "1. Observe CORS headers with wildcard and credentials enabled\n" +
                    "2. Any malicious site can make authenticated requests\n" +
                    "3. User sessions and tokens are exposed"
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        return new MisconfigTestResult(vulnerabilities, 1);
    }

    /**
     * Test for dangerous HTTP methods.
     */
    private MisconfigTestResult testDangerousMethods(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing dangerous HTTP methods for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int testsExecuted = 0;

        for (String method : DANGEROUS_METHODS) {
            TestRequest request = TestRequest.builder()
                .url(url)
                .method(method)
                .headers(context.getAuthHeaders())
                .build();

            TestResponse response = executeTest(httpClient, request, "Method Test: " + method);
            testsExecuted++;

            // If dangerous method is accepted
            if (response.getStatusCode() != 405 && response.getStatusCode() < 400) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION)
                    .severity(Severity.MEDIUM)
                    .endpoint(endpoint)
                    .title("Dangerous HTTP Method Enabled: " + method)
                    .description(
                        "The endpoint accepts potentially dangerous HTTP method '" + method + "'. " +
                        "Methods like TRACE can be used for Cross-Site Tracing (XST) attacks, " +
                        "and unnecessary methods increase the attack surface."
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("method", method)
                    .addEvidence("statusCode", response.getStatusCode())
                    .addRecommendation("Disable TRACE and TRACK methods")
                    .addRecommendation("Only enable necessary HTTP methods (GET, POST, PUT, PATCH, DELETE)")
                    .addRecommendation("Return 405 Method Not Allowed for unsupported methods")
                    .reproductionSteps(
                        "1. Send " + method + " request to " + url + "\n" +
                        "2. Observe " + response.getStatusCode() + " response (expected 405)\n" +
                        "3. Dangerous method is enabled"
                    )
                    .build();

                vulnerabilities.add(vulnerability);
            }
        }

        return new MisconfigTestResult(vulnerabilities, testsExecuted);
    }

    /**
     * Test for verbose error messages.
     */
    private MisconfigTestResult testVerboseErrors(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing verbose error messages for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        // Try to trigger an error with invalid input
        TestRequest request = TestRequest.builder()
            .url(url + "?invalid=../../../../etc/passwd&id=99999999&test='\"<script>")
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Verbose Error Test");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        String body = response.getBody();
        List<String> foundPatterns = new ArrayList<>();

        // Check for error patterns in response
        for (String pattern : ERROR_PATTERNS) {
            if (body.matches("(?s).*" + pattern + ".*")) {
                foundPatterns.add(pattern);
            }
        }

        if (!foundPatterns.isEmpty() && (response.getStatusCode() >= 400 || response.getStatusCode() == 200)) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.MEDIUM)
                .endpoint(endpoint)
                .title("Verbose Error Messages with Stack Traces")
                .description(
                    "The API returns detailed error messages including stack traces, " +
                    "file paths, or internal implementation details. This information " +
                    "disclosure helps attackers understand the application structure " +
                    "and identify potential vulnerabilities. Found patterns: " + foundPatterns
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("errorPatterns", foundPatterns)
                .addEvidence("statusCode", response.getStatusCode())
                .addEvidence("responseLength", body.length())
                .addRecommendation("Implement generic error messages for production")
                .addRecommendation("Log detailed errors server-side only")
                .addRecommendation("Disable debug mode in production")
                .addRecommendation("Use custom error pages without technical details")
                .reproductionSteps(
                    "1. Send malformed request to " + url + "\n" +
                    "2. Observe verbose error response\n" +
                    "3. Response contains: " + foundPatterns
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        return new MisconfigTestResult(vulnerabilities, 1);
    }

    /**
     * Test cache control on sensitive endpoints.
     */
    private MisconfigTestResult testCacheControl(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing cache control for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Cache Control Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();

        String cacheControl = getHeader(response, "Cache-Control");
        String pragma = getHeader(response, "Pragma");

        // Check if sensitive data might be cached
        if (cacheControl == null || (!cacheControl.contains("no-store") && !cacheControl.contains("no-cache"))) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.MEDIUM)
                .endpoint(endpoint)
                .title("Missing Cache Control on Sensitive Endpoint")
                .description(
                    "The sensitive endpoint does not have proper cache control headers. " +
                    "This may allow sensitive data to be cached by browsers or proxies, " +
                    "potentially exposing user data to unauthorized parties."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("Cache-Control", cacheControl != null ? cacheControl : "missing")
                .addEvidence("Pragma", pragma != null ? pragma : "missing")
                .addRecommendation("Add Cache-Control: no-store, no-cache, must-revalidate")
                .addRecommendation("Add Pragma: no-cache for HTTP/1.0 compatibility")
                .addRecommendation("Set appropriate Expires headers")
                .reproductionSteps(
                    "1. Send request to sensitive endpoint: " + url + "\n" +
                    "2. Check Cache-Control header\n" +
                    "3. Sensitive data may be cached"
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        return new MisconfigTestResult(vulnerabilities, 1);
    }

    /**
     * Check if header exists in response (case-insensitive).
     */
    private boolean hasHeader(TestResponse response, String headerName) {
        return response.getHeaders().keySet().stream()
            .anyMatch(key -> key.equalsIgnoreCase(headerName));
    }

    /**
     * Get header value from response (case-insensitive).
     */
    private String getHeader(TestResponse response, String headerName) {
        return response.getHeaders().entrySet().stream()
            .filter(entry -> entry.getKey().equalsIgnoreCase(headerName))
            .map(Map.Entry::getValue)
            .filter(list -> !list.isEmpty())
            .map(list -> list.get(0))
            .findFirst()
            .orElse(null);
    }

    /**
     * Check if endpoint is sensitive (requires stricter security).
     */
    private boolean isSensitiveEndpoint(ApiEndpoint endpoint) {
        String path = endpoint.getPath().toLowerCase();
        return path.contains("auth") || path.contains("login") ||
               path.contains("password") || path.contains("user") ||
               path.contains("account") || path.contains("admin") ||
               path.contains("payment") || path.contains("transaction") ||
               path.contains("transfer") || path.contains("profile");
    }

    /**
     * Result of a security misconfiguration test case.
     */
    private record MisconfigTestResult(
        List<VulnerabilityReport> vulnerabilities,
        int testsExecuted
    ) {}
}
