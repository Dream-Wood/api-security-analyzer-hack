package active.scanner.businessflow;

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
 * Scanner for detecting Unrestricted Access to Sensitive Business Flows vulnerabilities.
 *
 * <p>Unrestricted Access to Sensitive Business Flows occurs when APIs do not properly
 * limit how sensitive business operations can be consumed, allowing attackers to abuse
 * business logic through excessive or automated usage.
 *
 * <p>This scanner tests for:
 * <ul>
 *   <li>Missing rate limiting on sensitive business operations</li>
 *   <li>Lack of protection against automated/scripted abuse</li>
 *   <li>Absence of CAPTCHA or similar challenges on critical flows</li>
 *   <li>No detection of abnormal business flow patterns</li>
 *   <li>Missing transaction velocity checks</li>
 * </ul>
 *
 * <p>Based on OWASP API Security Top 10 - API6:2023
 */
public final class UnrestrictedBusinessFlowScanner extends AbstractScanner {
    private static final String SCANNER_ID = "unrestricted-business-flow-scanner";
    private static final String SCANNER_NAME = "Unrestricted Business Flow Scanner";
    private static final String SCANNER_DESCRIPTION =
        "Detects unrestricted access to sensitive business flows including missing rate limits and automation protection";

    // Sensitive business operation patterns
    private static final List<String> SENSITIVE_OPERATIONS = List.of(
        "purchase", "buy", "order", "payment", "transfer", "withdraw",
        "create", "register", "signup", "vote", "comment", "post",
        "delete", "reset", "verify", "confirm", "approve", "submit"
    );

    // Number of rapid requests to test rate limiting
    private static final int RATE_LIMIT_TEST_COUNT = 10;

    // Delay between requests in milliseconds (very short to test rate limiting)
    private static final int REQUEST_DELAY_MS = 50;

    public UnrestrictedBusinessFlowScanner() {
        super();
    }

    public UnrestrictedBusinessFlowScanner(ScannerConfig config) {
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
        return List.of(VulnerabilityReport.VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW);
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        String path = endpoint.getPath().toLowerCase();
        String method = endpoint.getMethod().toUpperCase();

        // Skip obvious monitoring/health endpoints
        if (path.contains("/health") ||
            path.contains("/status") ||
            path.contains("/ping") ||
            path.contains("/metrics")) {
            return false;
        }

        // This scanner is most relevant for:
        // 1. State-changing operations (POST, PUT, PATCH, DELETE)
        // 2. Endpoints with sensitive business operation keywords
        if (method.equals("POST") || method.equals("PUT") ||
            method.equals("PATCH") || method.equals("DELETE")) {
            return true;
        }

        // Also check if path contains sensitive operation keywords
        return SENSITIVE_OPERATIONS.stream()
            .anyMatch(path::contains);
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int totalTests = 0;

        // Test Case 1: Rate limiting on sensitive operations
        BusinessFlowTestResult rateLimitTest = testRateLimiting(endpoint, httpClient, context);
        totalTests += rateLimitTest.testsExecuted();
        rateLimitTest.vulnerability().ifPresent(vulnerabilities::add);

        // Test Case 2: Automated request detection
        BusinessFlowTestResult automationTest = testAutomationDetection(endpoint, httpClient, context);
        totalTests += automationTest.testsExecuted();
        automationTest.vulnerability().ifPresent(vulnerabilities::add);

        return createSuccessResult(endpoint, vulnerabilities, totalTests, startTime);
    }

    /**
     * Test if rate limiting is implemented on the endpoint.
     * Sends rapid successive requests to check if the API throttles requests.
     */
    private BusinessFlowTestResult testRateLimiting(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing rate limiting for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());
        int successfulRequests = 0;
        int rateLimitedRequests = 0;
        List<Integer> statusCodes = new ArrayList<>();

        // Send rapid requests
        for (int i = 0; i < RATE_LIMIT_TEST_COUNT; i++) {
            TestRequest request = TestRequest.builder()
                .url(url)
                .method(endpoint.getMethod())
                .headers(context.getAuthHeaders())
                .build();

            TestResponse response = executeTest(httpClient, request,
                "Rate Limit Test " + (i + 1) + "/" + RATE_LIMIT_TEST_COUNT);

            int statusCode = response.getStatusCode();
            statusCodes.add(statusCode);

            // Check for rate limiting responses
            if (statusCode == 429 || statusCode == 503) {
                rateLimitedRequests++;
            } else if (statusCode >= 200 && statusCode < 300) {
                successfulRequests++;
            }

            // Small delay to simulate rapid requests
            try {
                Thread.sleep(REQUEST_DELAY_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        // If most requests succeed without rate limiting, it's a vulnerability
        if (successfulRequests >= RATE_LIMIT_TEST_COUNT - 2 && rateLimitedRequests == 0) {
            Severity severity = determineSeverityByOperation(endpoint);

            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW)
                .severity(severity)
                .endpoint(endpoint)
                .title("Missing Rate Limiting on Sensitive Business Flow")
                .description(
                    "The endpoint allows unlimited rapid requests without any rate limiting. " +
                    "This can be exploited to automate sensitive business operations, leading to " +
                    "business logic abuse, inventory depletion, financial fraud, or resource exhaustion. " +
                    "Sent " + RATE_LIMIT_TEST_COUNT + " rapid requests and all " + successfulRequests +
                    " succeeded without throttling."
                )
                .addEvidence("totalRequests", RATE_LIMIT_TEST_COUNT)
                .addEvidence("successfulRequests", successfulRequests)
                .addEvidence("rateLimitedRequests", rateLimitedRequests)
                .addEvidence("statusCodes", statusCodes)
                .addEvidence("requestDelayMs", REQUEST_DELAY_MS)
                .addRecommendation("Implement rate limiting on all sensitive business operations")
                .addRecommendation("Use sliding window or token bucket algorithms for rate limiting")
                .addRecommendation("Return 429 Too Many Requests when rate limit is exceeded")
                .addRecommendation("Add Retry-After header to indicate when to retry")
                .addRecommendation("Implement per-user and per-IP rate limiting")
                .addRecommendation("Monitor and alert on unusual request patterns")
                .reproductionSteps(
                    "1. Send " + RATE_LIMIT_TEST_COUNT + " rapid " + endpoint.getMethod() + " requests to " + url + "\n" +
                    "2. Observe that all requests succeed without rate limiting\n" +
                    "3. Status codes received: " + statusCodes + "\n" +
                    "4. Expected: 429 Too Many Requests after a threshold"
                )
                .build();

            return new BusinessFlowTestResult(Optional.of(vulnerability), RATE_LIMIT_TEST_COUNT);
        }

        return new BusinessFlowTestResult(Optional.empty(), RATE_LIMIT_TEST_COUNT);
    }

    /**
     * Test if the endpoint has protection against automated/scripted requests.
     * Checks for CAPTCHA challenges, bot detection, or other automation prevention mechanisms.
     */
    private BusinessFlowTestResult testAutomationDetection(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing automation detection for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        // Send requests with typical bot/automation indicators
        Map<String, String> botHeaders = new HashMap<>(context.getAuthHeaders());
        botHeaders.put("User-Agent", "Python/3.9 requests/2.28.0");
        botHeaders.put("X-Automation", "true");

        TestRequest botRequest = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(botHeaders)
            .build();

        TestResponse botResponse = executeTest(httpClient, botRequest, "Automation Detection Test");

        // Check if request with bot indicators succeeds
        if (isSuccessfulUnauthorizedAccess(botResponse)) {
            // Additional check: send multiple automated-looking requests
            int automatedSuccesses = 1; // Already have one success
            int automatedTests = 1;

            for (int i = 0; i < 4; i++) {
                TestResponse response = executeTest(httpClient, botRequest,
                    "Automated Request " + (i + 2));
                automatedTests++;

                if (isSuccessfulUnauthorizedAccess(response)) {
                    automatedSuccesses++;
                }

                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            // If most automated requests succeed, it's a vulnerability
            if (automatedSuccesses >= 4) {
                Severity severity = determineSeverityByOperation(endpoint);

                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW)
                    .severity(severity)
                    .endpoint(endpoint)
                    .title("Missing Automation Protection on Sensitive Business Flow")
                    .description(
                        "The endpoint accepts automated/scripted requests without any bot detection " +
                        "or CAPTCHA challenges. Requests with clear automation indicators " +
                        "(bot user-agent, automation headers) are processed successfully. " +
                        "This allows attackers to automate abuse of sensitive business operations " +
                        "at scale."
                    )
                    .exploitRequest(botRequest)
                    .exploitResponse(botResponse)
                    .addEvidence("automatedTests", automatedTests)
                    .addEvidence("automatedSuccesses", automatedSuccesses)
                    .addEvidence("userAgent", "Python/3.9 requests/2.28.0")
                    .addEvidence("statusCode", botResponse.getStatusCode())
                    .addRecommendation("Implement CAPTCHA challenges for sensitive operations")
                    .addRecommendation("Add bot detection mechanisms (behavioral analysis, fingerprinting)")
                    .addRecommendation("Monitor for automation patterns (timing, user-agent, request patterns)")
                    .addRecommendation("Require additional verification for suspicious activity")
                    .addRecommendation("Implement device fingerprinting and trust scoring")
                    .addRecommendation("Add progressive delays for repeated operations")
                    .reproductionSteps(
                        "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                        "2. Use bot-like User-Agent: 'Python/3.9 requests/2.28.0'\n" +
                        "3. Add X-Automation header\n" +
                        "4. Observe " + botResponse.getStatusCode() + " success response\n" +
                        "5. Repeat multiple times - all requests succeed without challenge"
                    )
                    .build();

                return new BusinessFlowTestResult(Optional.of(vulnerability), automatedTests);
            }
        }

        return new BusinessFlowTestResult(Optional.empty(), 1);
    }

    /**
     * Determine vulnerability severity based on the type of operation.
     */
    private Severity determineSeverityByOperation(ApiEndpoint endpoint) {
        String path = endpoint.getPath().toLowerCase();
        String method = endpoint.getMethod().toUpperCase();

        // Critical operations - financial, deletion, authentication
        if (path.contains("payment") || path.contains("purchase") || path.contains("buy") ||
            path.contains("transfer") || path.contains("withdraw") || path.contains("delete") ||
            path.contains("reset") || method.equals("DELETE")) {
            return Severity.CRITICAL;
        }

        // High severity - account operations, data modification
        if (path.contains("register") || path.contains("signup") || path.contains("create") ||
            path.contains("verify") || path.contains("confirm") || path.contains("approve") ||
            method.equals("POST") || method.equals("PUT") || method.equals("PATCH")) {
            return Severity.HIGH;
        }

        // Medium for other operations
        return Severity.MEDIUM;
    }

    /**
     * Result of a business flow test case.
     */
    private record BusinessFlowTestResult(
        Optional<VulnerabilityReport> vulnerability,
        int testsExecuted
    ) {}
}
