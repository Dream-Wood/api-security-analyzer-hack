package active.scanner.unsafeapi;

import active.http.HttpClient;
import active.model.ApiEndpoint;
import active.model.TestRequest;
import active.model.TestResponse;
import active.model.VulnerabilityReport;
import active.scanner.AbstractScanner;
import active.scanner.ScanContext;
import active.scanner.ScanResult;
import active.scanner.ScannerConfig;
import model.ParameterSpec.ParameterLocation;
import model.Severity;

import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Scanner for detecting Unsafe Consumption of APIs vulnerabilities.
 *
 * <p>Unsafe Consumption of APIs occurs when applications blindly trust and process
 * data from third-party APIs without proper validation, leading to various security
 * risks including injection attacks, SSRF, and data integrity issues.
 *
 * <p>This scanner tests for:
 * <ul>
 *   <li>Lack of input validation on responses from integrated APIs</li>
 *   <li>Missing timeout configurations for external API calls</li>
 *   <li>Blind trust in third-party data without sanitization</li>
 *   <li>Insufficient error handling for external API failures</li>
 *   <li>Potential SSRF through URL parameters</li>
 *   <li>Missing validation of redirect chains from external APIs</li>
 * </ul>
 *
 * <p>Based on OWASP API Security Top 10 - API10:2023
 */
public final class UnsafeApiConsumptionScanner extends AbstractScanner {
    private static final String SCANNER_ID = "unsafe-api-consumption-scanner";
    private static final String SCANNER_NAME = "Unsafe API Consumption Scanner";
    private static final String SCANNER_DESCRIPTION =
        "Detects unsafe consumption of APIs including lack of validation, timeout issues, and blind trust in external data";

    // Parameter names that might indicate external API consumption
    private static final List<String> EXTERNAL_API_PARAMS = List.of(
        "url", "callback", "webhook", "api", "endpoint", "service",
        "fetch", "proxy", "redirect", "external", "remote", "feed"
    );

    // Response headers that indicate integration with external services
    private static final List<String> INTEGRATION_HEADERS = List.of(
        "X-Proxy-URL",
        "X-Upstream-URL",
        "X-Backend-Server",
        "X-External-API",
        "Via"
    );

    // Patterns indicating direct proxy/passthrough of external data
    private static final List<String> PASSTHROUGH_INDICATORS = List.of(
        "X-Forwarded",
        "X-Real-IP",
        "X-Proxied-By",
        "X-API-Gateway"
    );

    // SSRF test payloads - internal addresses
    private static final List<String> SSRF_TEST_URLS = List.of(
        "http://127.0.0.1:80",
        "http://localhost:80",
        "http://169.254.169.254/latest/meta-data/",  // AWS metadata
        "http://metadata.google.internal/computeMetadata/v1/",  // GCP metadata
        "http://[::1]:80"
    );

    public UnsafeApiConsumptionScanner() {
        super();
    }

    public UnsafeApiConsumptionScanner(ScannerConfig config) {
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
        return List.of(VulnerabilityReport.VulnerabilityType.UNSAFE_API_CONSUMPTION);
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // Apply to endpoints that might consume external APIs
        String path = endpoint.getPath().toLowerCase();

        // Check if path suggests external API consumption
        boolean hasExternalApiPath = path.contains("proxy") || path.contains("webhook") ||
                                     path.contains("callback") || path.contains("fetch") ||
                                     path.contains("external") || path.contains("integrate");

        // Check if endpoint accepts URL-like parameters
        boolean hasUrlParams = endpoint.getParameters().stream()
            .anyMatch(param -> EXTERNAL_API_PARAMS.stream()
                .anyMatch(apiParam -> param.getName().toLowerCase().contains(apiParam)));

        return hasExternalApiPath || hasUrlParams || true; // Check all by default
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int totalTests = 0;

        // Test Case 1: Missing timeout headers/indicators
        UnsafeApiTestResult timeoutTest = testTimeoutConfiguration(endpoint, httpClient, context);
        totalTests += timeoutTest.testsExecuted();
        vulnerabilities.addAll(timeoutTest.vulnerabilities());

        // Test Case 2: Check for external API integration indicators
        UnsafeApiTestResult integrationTest = testExternalIntegration(endpoint, httpClient, context);
        totalTests += integrationTest.testsExecuted();
        vulnerabilities.addAll(integrationTest.vulnerabilities());

        // Test Case 3: SSRF potential through URL parameters
        if (hasUrlParameter(endpoint)) {
            UnsafeApiTestResult ssrfTest = testSsrfVulnerability(endpoint, httpClient, context);
            totalTests += ssrfTest.testsExecuted();
            vulnerabilities.addAll(ssrfTest.vulnerabilities());
        }

        // Test Case 4: Unsafe redirect following
        UnsafeApiTestResult redirectTest = testUnsafeRedirects(endpoint, httpClient, context);
        totalTests += redirectTest.testsExecuted();
        vulnerabilities.addAll(redirectTest.vulnerabilities());

        // Test Case 5: Missing validation on external data
        UnsafeApiTestResult validationTest = testExternalDataValidation(endpoint, httpClient, context);
        totalTests += validationTest.testsExecuted();
        vulnerabilities.addAll(validationTest.vulnerabilities());

        return createSuccessResult(endpoint, vulnerabilities, totalTests, startTime);
    }

    /**
     * Test for missing timeout configuration indicators.
     */
    private UnsafeApiTestResult testTimeoutConfiguration(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing timeout configuration for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Timeout Configuration Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();

        // Check for timeout-related headers (custom headers that might indicate timeout handling)
        String timeoutHeader = getHeader(response, "X-Timeout");
        String maxWaitHeader = getHeader(response, "X-Max-Wait-Time");
        String upstreamTimeout = getHeader(response, "X-Upstream-Timeout");

        // Check response time - if it's suspiciously long, there might be no timeout
        boolean hasTimeoutIndicators = timeoutHeader != null || maxWaitHeader != null || upstreamTimeout != null;

        // Check if this endpoint might consume external APIs
        boolean mightConsumeExternalApi = hasExternalApiIndicators(endpoint, response);

        if (mightConsumeExternalApi && !hasTimeoutIndicators) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.UNSAFE_API_CONSUMPTION)
                .severity(Severity.MEDIUM)
                .endpoint(endpoint)
                .title("Missing Timeout Configuration for External API Calls")
                .description(
                    "The endpoint appears to integrate with external APIs but does not expose " +
                    "timeout configuration indicators. Without proper timeouts, the application " +
                    "may hang indefinitely waiting for slow or unresponsive third-party services, " +
                    "leading to resource exhaustion and denial of service. External API calls " +
                    "should have strict timeout limits to prevent cascading failures."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("hasTimeoutHeaders", false)
                .addEvidence("consumesExternalApi", true)
                .addRecommendation("Implement connection timeouts for all external API calls (recommended: 5-10 seconds)")
                .addRecommendation("Set read timeouts to prevent hanging on slow responses (recommended: 30 seconds)")
                .addRecommendation("Implement circuit breaker pattern for external service failures")
                .addRecommendation("Add timeout configuration headers to indicate proper handling")
                .addRecommendation("Use async processing with timeout limits for long-running external calls")
                .reproductionSteps(
                    "1. Send request to " + url + "\n" +
                    "2. Observe no timeout-related headers\n" +
                    "3. Endpoint may hang indefinitely on slow external APIs"
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        return new UnsafeApiTestResult(vulnerabilities, 1);
    }

    /**
     * Test for unsafe external API integration.
     */
    private UnsafeApiTestResult testExternalIntegration(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing external API integration for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "External Integration Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();

        // Check for headers indicating external integration
        Map<String, String> integrationHeaders = new HashMap<>();
        for (String header : INTEGRATION_HEADERS) {
            String value = getHeader(response, header);
            if (value != null) {
                integrationHeaders.put(header, value);
            }
        }

        // Check for passthrough indicators
        Map<String, String> passthroughHeaders = new HashMap<>();
        for (String header : PASSTHROUGH_INDICATORS) {
            String value = getHeader(response, header);
            if (value != null) {
                passthroughHeaders.put(header, value);
            }
        }

        if (!integrationHeaders.isEmpty() || !passthroughHeaders.isEmpty()) {
            // Check for validation headers
            String contentValidation = getHeader(response, "X-Content-Validated");
            String dataIntegrity = getHeader(response, "X-Data-Integrity-Check");

            boolean hasValidationIndicators = contentValidation != null || dataIntegrity != null;

            if (!hasValidationIndicators) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.UNSAFE_API_CONSUMPTION)
                    .severity(Severity.HIGH)
                    .endpoint(endpoint)
                    .title("Unsafe External API Integration Without Validation")
                    .description(
                        "The endpoint integrates with external APIs but shows no evidence of " +
                        "data validation or integrity checks. Blindly trusting external data can " +
                        "lead to injection attacks, data corruption, and business logic bypasses. " +
                        "All data from external sources must be validated, sanitized, and verified " +
                        "before use. Integration headers found: " + integrationHeaders
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("integrationHeaders", integrationHeaders)
                    .addEvidence("passthroughHeaders", passthroughHeaders)
                    .addEvidence("hasValidationIndicators", false)
                    .addRecommendation("Validate all data received from external APIs against expected schemas")
                    .addRecommendation("Sanitize external data before use to prevent injection attacks")
                    .addRecommendation("Implement integrity checks (signatures, checksums) for critical external data")
                    .addRecommendation("Never trust external API responses without validation")
                    .addRecommendation("Use allowlists for expected data formats and values")
                    .addRecommendation("Implement rate limiting for external API consumption")
                    .reproductionSteps(
                        "1. Send request to " + url + "\n" +
                        "2. Observe external integration headers: " + integrationHeaders + "\n" +
                        "3. No validation headers found\n" +
                        "4. External data may be consumed without proper validation"
                    )
                    .build();

                vulnerabilities.add(vulnerability);
            }
        }

        return new UnsafeApiTestResult(vulnerabilities, 1);
    }

    /**
     * Test for SSRF vulnerability through URL parameters.
     */
    private UnsafeApiTestResult testSsrfVulnerability(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing SSRF vulnerability for: " + endpoint);

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int testsExecuted = 0;

        // Find URL parameters
        var urlParams = endpoint.getParameters().stream()
            .filter(param -> EXTERNAL_API_PARAMS.stream()
                .anyMatch(apiParam -> param.getName().toLowerCase().contains(apiParam)))
            .toList();

        for (var param : urlParams) {
            for (String ssrfUrl : SSRF_TEST_URLS) {
                String url = context.buildUrl(endpoint.getPath());

                Map<String, String> headers = new HashMap<>(context.getAuthHeaders());

                TestRequest.Builder requestBuilder = TestRequest.builder()
                    .url(url)
                    .method(endpoint.getMethod())
                    .headers(headers);

                // Add SSRF payload based on parameter location
                if (param.getLocation() == ParameterLocation.QUERY) {
                    requestBuilder.url(url + "?" + param.getName() + "=" + ssrfUrl);
                } else if (param.getLocation() == ParameterLocation.HEADER) {
                    headers.put(param.getName(), ssrfUrl);
                } else {
                    // For body/path parameters, add to body as JSON
                    requestBuilder.body("{\"" + param.getName() + "\": \"" + ssrfUrl + "\"}");
                    headers.put("Content-Type", "application/json");
                }

                TestRequest request = requestBuilder.build();
                TestResponse response = executeTest(httpClient, request, "SSRF Test: " + ssrfUrl);
                testsExecuted++;

                // Check if SSRF might be possible
                // Don't mark as vulnerable based on status alone - this would require actual SSRF detection
                // Instead, check for indicators that the URL parameter is not properly validated
                if (response.getStatusCode() == 200 || response.getStatusCode() == 500) {
                    String body = response.getBody();

                    // Look for indicators that the URL was processed
                    boolean mightBeVulnerable = body.contains("localhost") ||
                                               body.contains("127.0.0.1") ||
                                               body.contains("metadata") ||
                                               body.contains("internal") ||
                                               response.getStatusCode() == 500; // Server error might indicate SSRF attempt

                    if (mightBeVulnerable) {
                        VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                            .type(VulnerabilityReport.VulnerabilityType.UNSAFE_API_CONSUMPTION)
                            .severity(Severity.CRITICAL)
                            .endpoint(endpoint)
                            .title("Potential SSRF Through Unsafe URL Parameter Consumption")
                            .description(
                                "The endpoint accepts URL parameters and may not properly validate them, " +
                                "potentially allowing Server-Side Request Forgery (SSRF) attacks. " +
                                "When consuming external APIs through user-controlled URLs, applications " +
                                "must validate against allowlists and block access to internal resources. " +
                                "SSRF can lead to internal network scanning, cloud metadata exposure, " +
                                "and unauthorized access to internal services."
                            )
                            .exploitRequest(request)
                            .exploitResponse(response)
                            .addEvidence("parameterName", param.getName())
                            .addEvidence("ssrfPayload", ssrfUrl)
                            .addEvidence("statusCode", response.getStatusCode())
                            .addRecommendation("Implement strict URL validation with allowlist of permitted domains")
                            .addRecommendation("Block access to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)")
                            .addRecommendation("Block access to cloud metadata endpoints (169.254.169.254)")
                            .addRecommendation("Use DNS resolution checks to prevent TOCTOU attacks")
                            .addRecommendation("Implement network-level controls to isolate external API calls")
                            .addRecommendation("Never allow user-controlled URLs without validation")
                            .reproductionSteps(
                                "1. Send request with URL parameter: " + param.getName() + "=" + ssrfUrl + "\n" +
                                "2. Server processes the internal URL\n" +
                                "3. Potential SSRF vulnerability exists"
                            )
                            .build();

                        vulnerabilities.add(vulnerability);
                        break; // One finding per parameter is enough
                    }
                }
            }
        }

        return new UnsafeApiTestResult(vulnerabilities, testsExecuted);
    }

    /**
     * Test for unsafe redirect following.
     */
    private UnsafeApiTestResult testUnsafeRedirects(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing unsafe redirect handling for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Redirect Handling Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();

        // Check if response has redirect-related headers
        String location = getHeader(response, "Location");
        boolean isRedirect = response.getStatusCode() >= 300 && response.getStatusCode() < 400;

        if (isRedirect && location != null) {
            // Check for redirect validation headers
            String redirectValidation = getHeader(response, "X-Redirect-Validated");
            String followRedirects = getHeader(response, "X-Follow-Redirects");

            if (redirectValidation == null && followRedirects == null) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.UNSAFE_API_CONSUMPTION)
                    .severity(Severity.MEDIUM)
                    .endpoint(endpoint)
                    .title("Potentially Unsafe Redirect Following")
                    .description(
                        "The endpoint issues redirects but shows no evidence of redirect validation. " +
                        "When consuming external APIs that may redirect, applications must validate " +
                        "redirect targets to prevent attacks through malicious redirects to internal " +
                        "resources or unexpected domains. Unvalidated redirects in API consumption " +
                        "can lead to SSRF and data leakage."
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("redirectLocation", location)
                    .addEvidence("statusCode", response.getStatusCode())
                    .addRecommendation("Validate all redirect locations against allowlist")
                    .addRecommendation("Limit number of redirect hops (recommended: max 3)")
                    .addRecommendation("Prevent redirects to internal IP addresses")
                    .addRecommendation("Add X-Redirect-Validated header to indicate safe handling")
                    .reproductionSteps(
                        "1. Send request to " + url + "\n" +
                        "2. Server responds with redirect to: " + location + "\n" +
                        "3. No redirect validation indicators found"
                    )
                    .build();

                vulnerabilities.add(vulnerability);
            }
        }

        return new UnsafeApiTestResult(vulnerabilities, 1);
    }

    /**
     * Test for missing validation on external data consumption.
     */
    private UnsafeApiTestResult testExternalDataValidation(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing external data validation for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        // Send request with potentially malicious content that might come from external API
        Map<String, String> headers = new HashMap<>(context.getAuthHeaders());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(headers)
            .build();

        TestResponse response = executeTest(httpClient, request, "External Data Validation Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();

        // Check for security headers that indicate validation
        String contentSecurityPolicy = getHeader(response, "Content-Security-Policy");
        String xContentTypeOptions = getHeader(response, "X-Content-Type-Options");
        String inputValidation = getHeader(response, "X-Input-Validated");

        // Check if endpoint might consume external data
        boolean mightConsumeExternal = hasExternalApiIndicators(endpoint, response);

        if (mightConsumeExternal) {
            boolean hasValidationIndicators = inputValidation != null;

            if (!hasValidationIndicators) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.UNSAFE_API_CONSUMPTION)
                    .severity(Severity.MEDIUM)
                    .endpoint(endpoint)
                    .title("Missing Input Validation on External Data Consumption")
                    .description(
                        "The endpoint may consume data from external APIs without proper validation. " +
                        "All data from external sources must be validated against expected schemas, " +
                        "sanitized to prevent injection attacks, and verified for integrity. " +
                        "Unsafe consumption of external data can lead to injection vulnerabilities, " +
                        "business logic bypasses, and data corruption."
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("consumesExternalApi", true)
                    .addEvidence("hasInputValidation", false)
                    .addRecommendation("Implement schema validation for all external API responses")
                    .addRecommendation("Sanitize external data before processing or storage")
                    .addRecommendation("Use type-safe parsing and avoid dynamic evaluation")
                    .addRecommendation("Implement data integrity checks for critical external data")
                    .addRecommendation("Log and monitor anomalies in external data")
                    .reproductionSteps(
                        "1. Endpoint consumes data from external APIs\n" +
                        "2. No validation indicators in response headers\n" +
                        "3. External data may be used without proper validation"
                    )
                    .build();

                vulnerabilities.add(vulnerability);
            }
        }

        return new UnsafeApiTestResult(vulnerabilities, 1);
    }

    /**
     * Check if endpoint has URL parameters.
     */
    private boolean hasUrlParameter(ApiEndpoint endpoint) {
        return endpoint.getParameters().stream()
            .anyMatch(param -> EXTERNAL_API_PARAMS.stream()
                .anyMatch(apiParam -> param.getName().toLowerCase().contains(apiParam)));
    }

    /**
     * Check if endpoint has indicators of external API consumption.
     */
    private boolean hasExternalApiIndicators(ApiEndpoint endpoint, TestResponse response) {
        String path = endpoint.getPath().toLowerCase();

        // Check path for external API indicators
        boolean hasExternalPath = path.contains("proxy") || path.contains("webhook") ||
                                  path.contains("callback") || path.contains("fetch") ||
                                  path.contains("external") || path.contains("integrate");

        // Check headers for integration indicators
        boolean hasIntegrationHeaders = INTEGRATION_HEADERS.stream()
            .anyMatch(header -> getHeader(response, header) != null);

        return hasExternalPath || hasIntegrationHeaders || hasUrlParameter(endpoint);
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
     * Result of an unsafe API consumption test case.
     */
    private record UnsafeApiTestResult(
        List<VulnerabilityReport> vulnerabilities,
        int testsExecuted
    ) {}
}
