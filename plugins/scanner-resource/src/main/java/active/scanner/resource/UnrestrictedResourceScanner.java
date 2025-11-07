package active.scanner.resource;

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
 * Scanner for detecting Unrestricted Resource Consumption vulnerabilities.
 *
 * <p>Unrestricted Resource Consumption occurs when an API does not properly limit
 * the resources consumed by client requests, leading to:
 * <ul>
 *   <li>Missing or inadequate rate limiting</li>
 *   <li>No limits on request payload size</li>
 *   <li>Unrestricted batch operations</li>
 *   <li>Resource-intensive operations without throttling</li>
 *   <li>Lack of pagination limits</li>
 *   <li>No timeouts for long-running operations</li>
 * </ul>
 *
 * <p>These issues can lead to:
 * <ul>
 *   <li>Denial of Service (DoS) attacks</li>
 *   <li>API performance degradation</li>
 *   <li>Increased infrastructure costs</li>
 *   <li>Service unavailability for legitimate users</li>
 * </ul>
 *
 * <p>Based on OWASP API Security Top 10 - API4:2023
 */
public final class UnrestrictedResourceScanner extends AbstractScanner {
    private static final String SCANNER_ID = "unrestricted-resource-scanner";
    private static final String SCANNER_NAME = "Unrestricted Resource Consumption Scanner";
    private static final String SCANNER_DESCRIPTION =
        "Detects missing rate limits, oversized payloads, and resource exhaustion vulnerabilities";

    // Rate limiting test parameters
    private static final int RATE_LIMIT_TEST_REQUESTS = 50;
    private static final int RATE_LIMIT_THRESHOLD = 40; // If more than 40/50 succeed, likely no rate limit
    private static final long RATE_LIMIT_WINDOW_MS = 5000; // 5 seconds

    // Payload size limits
    private static final int LARGE_PAYLOAD_SIZE = 10 * 1024 * 1024; // 10MB
    private static final int HUGE_PAYLOAD_SIZE = 50 * 1024 * 1024; // 50MB

    // Resource-intensive parameters
    private static final int[] PAGINATION_TEST_LIMITS = {1000, 10000, 100000, 1000000};
    private static final int[] PAGINATION_TEST_PAGES = {1000, 10000, 100000, Integer.MAX_VALUE};
    private static final int EXCESSIVE_BATCH_SIZE = 10000;

    public UnrestrictedResourceScanner() {
        super();
    }

    public UnrestrictedResourceScanner(ScannerConfig config) {
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
            VulnerabilityReport.VulnerabilityType.UNRESTRICTED_RESOURCE,
            VulnerabilityReport.VulnerabilityType.MISSING_RATE_LIMITING
        );
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // This scanner is applicable to most endpoints
        String path = endpoint.getPath().toLowerCase();

        // Skip obvious health/status endpoints
        if (path.contains("/health") ||
            path.contains("/status") ||
            path.contains("/ping") ||
            path.equals("/")) {
            return false;
        }

        // All HTTP methods can be tested for resource consumption
        return true;
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int totalTests = 0;

        // Test Case 1: Rate limiting
        ResourceTestResult rateLimitTest = testRateLimiting(endpoint, httpClient, context);
        totalTests += rateLimitTest.testsExecuted();
        rateLimitTest.vulnerability().ifPresent(vulnerabilities::add);

        // Test Case 2: Large payload handling (for POST/PUT/PATCH)
        if (endpoint.getMethod().equals("POST") ||
            endpoint.getMethod().equals("PUT") ||
            endpoint.getMethod().equals("PATCH")) {
            ResourceTestResult largePayloadTest = testLargePayload(endpoint, httpClient, context);
            totalTests += largePayloadTest.testsExecuted();
            largePayloadTest.vulnerability().ifPresent(vulnerabilities::add);
        }

        // Test Case 3: Resource-intensive parameters (for GET)
        if (endpoint.getMethod().equals("GET")) {
            ResourceTestResult paginationLimitTest = testExcessivePagination(endpoint, httpClient, context);
            totalTests += paginationLimitTest.testsExecuted();
            paginationLimitTest.vulnerability().ifPresent(vulnerabilities::add);

            // Test Case 3b: Page parameter abuse
            if (vulnerabilities.isEmpty()) {
                ResourceTestResult paginationPageTest = testExcessivePaginationPage(endpoint, httpClient, context);
                totalTests += paginationPageTest.testsExecuted();
                paginationPageTest.vulnerability().ifPresent(vulnerabilities::add);
            }
        }

        // Test Case 4: Batch operations without limits (for POST)
        if (endpoint.getMethod().equals("POST")) {
            ResourceTestResult batchTest = testUnlimitedBatchOperations(endpoint, httpClient, context);
            totalTests += batchTest.testsExecuted();
            batchTest.vulnerability().ifPresent(vulnerabilities::add);
        }

        // Test Case 5: Response size limits
        ResourceTestResult responseSizeTest = testResponseSizeLimits(endpoint, httpClient, context);
        totalTests += responseSizeTest.testsExecuted();
        responseSizeTest.vulnerability().ifPresent(vulnerabilities::add);

        return createSuccessResult(endpoint, vulnerabilities, totalTests, startTime);
    }

    /**
     * Test if endpoint has rate limiting implemented.
     */
    private ResourceTestResult testRateLimiting(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing rate limiting for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());
        int successfulRequests = 0;
        List<Integer> statusCodes = new ArrayList<>();
        long startTime = System.currentTimeMillis();

        // Send rapid requests
        for (int i = 0; i < RATE_LIMIT_TEST_REQUESTS; i++) {
            TestRequest.Builder requestBuilder = TestRequest.builder()
                .url(url)
                .method(endpoint.getMethod());

            if (context.getAuthHeaders() != null) {
                requestBuilder.headers(context.getAuthHeaders());
            }

            TestRequest request = requestBuilder.build();
            TestResponse response = executeTest(httpClient, request, "Rate Limit Test " + (i + 1));

            statusCodes.add(response.getStatusCode());

            // Count successful requests (2xx or 3xx)
            if (response.getStatusCode() >= 200 && response.getStatusCode() < 400) {
                successfulRequests++;
            }

            // Check if we got rate limited (429 Too Many Requests)
            if (response.getStatusCode() == 429) {
                logger.fine("Rate limit detected at request " + (i + 1));
                break;
            }

            // Stop if we've been testing for too long
            if (System.currentTimeMillis() - startTime > RATE_LIMIT_WINDOW_MS) {
                break;
            }
        }

        long elapsedTime = System.currentTimeMillis() - startTime;

        // If most requests succeeded without rate limiting, it's a vulnerability
        if (successfulRequests >= RATE_LIMIT_THRESHOLD) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.MISSING_RATE_LIMITING)
                .severity(Severity.HIGH)
                .endpoint(endpoint)
                .title("Missing or Inadequate Rate Limiting")
                .description(
                    "The endpoint does not implement adequate rate limiting. " +
                    "Successfully executed " + successfulRequests + " out of " + statusCodes.size() +
                    " requests in " + elapsedTime + "ms without being rate limited. " +
                    "This allows attackers to perform DoS attacks or brute force operations."
                )
                .addEvidence("successfulRequests", successfulRequests)
                .addEvidence("totalRequests", statusCodes.size())
                .addEvidence("elapsedTimeMs", elapsedTime)
                .addEvidence("requestsPerSecond", (successfulRequests * 1000.0) / elapsedTime)
                .addRecommendation("Implement rate limiting using sliding window or token bucket algorithms")
                .addRecommendation("Return 429 Too Many Requests status when rate limit is exceeded")
                .addRecommendation("Include Retry-After header in rate limit responses")
                .addRecommendation("Apply rate limits per user/IP and globally")
                .addRecommendation("Consider using API gateway with built-in rate limiting")
                .reproductionSteps(
                    "1. Send " + RATE_LIMIT_TEST_REQUESTS + " rapid requests to " + url + "\n" +
                    "2. Observe that most requests succeed without rate limiting\n" +
                    "3. Successful requests: " + successfulRequests + "/" + statusCodes.size()
                )
                .build();

            return new ResourceTestResult(Optional.of(vulnerability), statusCodes.size());
        }

        return new ResourceTestResult(Optional.empty(), statusCodes.size());
    }

    /**
     * Test if endpoint accepts excessively large payloads.
     */
    private ResourceTestResult testLargePayload(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing large payload handling for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        // Create a large JSON payload (10MB)
        String largePayload = generateLargeJsonPayload(LARGE_PAYLOAD_SIZE);

        TestRequest.Builder requestBuilder = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .body(largePayload)
            .addHeader("Content-Type", "application/json");

        if (context.getAuthHeaders() != null) {
            context.getAuthHeaders().forEach(requestBuilder::addHeader);
        }

        TestRequest request = requestBuilder.build();
        TestResponse response = executeTest(httpClient, request, "Large Payload Test");

        // If the server accepts the large payload (2xx or 5xx from processing), it's vulnerable
        if (response.getStatusCode() >= 200 && response.getStatusCode() < 300) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.UNRESTRICTED_RESOURCE)
                .severity(Severity.HIGH)
                .endpoint(endpoint)
                .title("Unrestricted Request Payload Size")
                .description(
                    "The endpoint accepts excessively large request payloads without limits. " +
                    "Successfully sent a " + (LARGE_PAYLOAD_SIZE / (1024 * 1024)) + "MB payload " +
                    "and received " + response.getStatusCode() + " status. " +
                    "This can lead to memory exhaustion, DoS, and increased processing costs."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("statusCode", response.getStatusCode())
                .addEvidence("payloadSizeMB", LARGE_PAYLOAD_SIZE / (1024 * 1024))
                .addRecommendation("Implement request body size limits (e.g., 1-10MB maximum)")
                .addRecommendation("Return 413 Payload Too Large for oversized requests")
                .addRecommendation("Configure web server/reverse proxy with size limits")
                .addRecommendation("Validate content length before processing")
                .reproductionSteps(
                    "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                    "2. Include " + (LARGE_PAYLOAD_SIZE / (1024 * 1024)) + "MB JSON payload\n" +
                    "3. Observe " + response.getStatusCode() + " response (expected 413)"
                )
                .build();

            return new ResourceTestResult(Optional.of(vulnerability), 1);
        }

        return new ResourceTestResult(Optional.empty(), 1);
    }

    /**
     * Test if endpoint handles excessive pagination parameters.
     */
    private ResourceTestResult testExcessivePagination(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing excessive pagination for: " + endpoint);

        // Test with increasingly large limit parameters
        for (int limit : PAGINATION_TEST_LIMITS) {
            String urlWithLimit = addQueryParameter(
                context.buildUrl(endpoint.getPath()),
                "limit",
                String.valueOf(limit)
            );

            TestRequest.Builder requestBuilder = TestRequest.builder()
                .url(urlWithLimit)
                .method(endpoint.getMethod());

            if (context.getAuthHeaders() != null) {
                requestBuilder.headers(context.getAuthHeaders());
            }

            TestRequest request = requestBuilder.build();
            TestResponse response = executeTest(httpClient, request, "Pagination Test: limit=" + limit);

            // If server accepts excessive pagination without error
            if (response.getStatusCode() >= 200 && response.getStatusCode() < 300) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.UNRESTRICTED_RESOURCE)
                    .severity(determinePaginationSeverity(limit))
                    .endpoint(endpoint)
                    .title("Unrestricted Pagination Limits")
                    .description(
                        "The endpoint accepts excessive pagination limit parameter (limit=" + limit + ") " +
                        "without proper validation. This can cause database/memory exhaustion, " +
                        "slow response times, and DoS conditions."
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("statusCode", response.getStatusCode())
                    .addEvidence("limitParameter", limit)
                    .addEvidence("responseSizeBytes", response.getBody() != null ? response.getBody().length() : 0)
                    .addRecommendation("Implement maximum pagination limit (e.g., 100-1000 items)")
                    .addRecommendation("Return 400 Bad Request for limits exceeding maximum")
                    .addRecommendation("Use cursor-based pagination for large datasets")
                    .addRecommendation("Document pagination limits in API documentation")
                    .reproductionSteps(
                        "1. Send GET request to " + urlWithLimit + "\n" +
                        "2. Include limit=" + limit + " parameter\n" +
                        "3. Observe server processes request without proper validation"
                    )
                    .build();

                return new ResourceTestResult(Optional.of(vulnerability), PAGINATION_TEST_LIMITS.length);
            }
        }

        return new ResourceTestResult(Optional.empty(), PAGINATION_TEST_LIMITS.length);
    }

    /**
     * Test if endpoint handles unlimited batch operations.
     */
    private ResourceTestResult testUnlimitedBatchOperations(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing unlimited batch operations for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        // Try to create a batch operation with many items
        String batchPayload = generateBatchPayload(EXCESSIVE_BATCH_SIZE);

        TestRequest.Builder requestBuilder = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .body(batchPayload)
            .addHeader("Content-Type", "application/json");

        if (context.getAuthHeaders() != null) {
            context.getAuthHeaders().forEach(requestBuilder::addHeader);
        }

        TestRequest request = requestBuilder.build();
        TestResponse response = executeTest(httpClient, request, "Batch Operations Test");

        // If server accepts large batch without limits
        if (response.getStatusCode() >= 200 && response.getStatusCode() < 300) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.UNRESTRICTED_RESOURCE)
                .severity(Severity.MEDIUM)
                .endpoint(endpoint)
                .title("Unlimited Batch Operations")
                .description(
                    "The endpoint accepts batch operations with " + EXCESSIVE_BATCH_SIZE + " items " +
                    "without proper limits. This can cause database locks, memory exhaustion, " +
                    "and impact service availability for other users."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("statusCode", response.getStatusCode())
                .addEvidence("batchSize", EXCESSIVE_BATCH_SIZE)
                .addRecommendation("Implement maximum batch size limits (e.g., 100-1000 items)")
                .addRecommendation("Return 400 Bad Request for oversized batches")
                .addRecommendation("Process large batches asynchronously with job queues")
                .addRecommendation("Implement timeouts for batch operations")
                .reproductionSteps(
                    "1. Send POST request to " + url + "\n" +
                    "2. Include batch payload with " + EXCESSIVE_BATCH_SIZE + " items\n" +
                    "3. Observe server processes entire batch without limits"
                )
                .build();

            return new ResourceTestResult(Optional.of(vulnerability), 1);
        }

        return new ResourceTestResult(Optional.empty(), 1);
    }

    /**
     * Test if endpoint has response size limits.
     */
    private ResourceTestResult testResponseSizeLimits(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing response size limits for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest.Builder requestBuilder = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod());

        if (context.getAuthHeaders() != null) {
            requestBuilder.headers(context.getAuthHeaders());
        }

        TestRequest request = requestBuilder.build();
        TestResponse response = executeTest(httpClient, request, "Response Size Test");

        // Check if response is excessively large (> 10MB)
        if (response.getBody() != null && response.getBody().length() > LARGE_PAYLOAD_SIZE) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.UNRESTRICTED_RESOURCE)
                .severity(Severity.MEDIUM)
                .endpoint(endpoint)
                .title("Unrestricted Response Size")
                .description(
                    "The endpoint returns excessively large responses (" +
                    (response.getBody().length() / (1024 * 1024)) + "MB). " +
                    "Large responses can exhaust client memory, increase bandwidth costs, " +
                    "and degrade service performance."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("statusCode", response.getStatusCode())
                .addEvidence("responseSizeMB", response.getBody().length() / (1024 * 1024))
                .addRecommendation("Implement pagination for large result sets")
                .addRecommendation("Limit maximum response size (e.g., 10MB)")
                .addRecommendation("Use streaming for large data transfers")
                .addRecommendation("Implement field filtering to reduce response size")
                .reproductionSteps(
                    "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                    "2. Observe large response size: " + (response.getBody().length() / (1024 * 1024)) + "MB"
                )
                .build();

            return new ResourceTestResult(Optional.of(vulnerability), 1);
        }

        return new ResourceTestResult(Optional.empty(), 1);
    }

    /**
     * Generate a large JSON payload of specified size.
     */
    private String generateLargeJsonPayload(int sizeBytes) {
        StringBuilder payload = new StringBuilder();
        payload.append("{\"data\":[");

        int itemSize = 100; // Approximate size per item
        int itemCount = sizeBytes / itemSize;

        for (int i = 0; i < itemCount; i++) {
            if (i > 0) {
                payload.append(",");
            }
            payload.append("{\"id\":").append(i)
                   .append(",\"value\":\"").append("x".repeat(50)).append("\"}");
        }

        payload.append("]}");
        return payload.toString();
    }

    /**
     * Generate a batch payload with many items.
     */
    private String generateBatchPayload(int itemCount) {
        StringBuilder payload = new StringBuilder();
        payload.append("{\"items\":[");

        for (int i = 0; i < itemCount; i++) {
            if (i > 0) {
                payload.append(",");
            }
            payload.append("{\"id\":").append(i).append("}");
        }

        payload.append("]}");
        return payload.toString();
    }

    /**
     * Add query parameter to URL.
     */
    private String addQueryParameter(String url, String param, String value) {
        String separator = url.contains("?") ? "&" : "?";
        return url + separator + param + "=" + value;
    }

    /**
     * Test if endpoint handles excessive page parameter values.
     * Large page numbers can cause database offset calculations to overflow or timeout.
     */
    private ResourceTestResult testExcessivePaginationPage(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing excessive pagination page parameter for: " + endpoint);

        // Test with increasingly large page numbers
        for (int page : PAGINATION_TEST_PAGES) {
            String urlWithPage = addQueryParameter(
                context.buildUrl(endpoint.getPath()),
                "page",
                String.valueOf(page)
            );

            TestRequest.Builder requestBuilder = TestRequest.builder()
                .url(urlWithPage)
                .method(endpoint.getMethod());

            if (context.getAuthHeaders() != null) {
                requestBuilder.headers(context.getAuthHeaders());
            }

            TestRequest request = requestBuilder.build();
            TestResponse response = executeTest(httpClient, request, "Page Test: page=" + page);

            // If server accepts excessive page numbers without error, it's vulnerable
            if (response.getStatusCode() >= 200 && response.getStatusCode() < 300) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.UNRESTRICTED_RESOURCE)
                    .severity(determinePageSeverity(page))
                    .endpoint(endpoint)
                    .title("Unrestricted Pagination Page Parameter")
                    .description(
                        "The endpoint accepts excessive page parameter values (page=" + page + ") " +
                        "without proper validation. Large page numbers can cause:\n" +
                        "- Database offset calculations to overflow (LIMIT x OFFSET y where y is huge)\n" +
                        "- Memory exhaustion from skipping millions of records\n" +
                        "- Query timeouts and database locks\n" +
                        "- DoS conditions affecting all users\n\n" +
                        "For example, with page=1000000 and limit=50, the database must skip " +
                        "50,000,000 records which is extremely resource-intensive."
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("statusCode", response.getStatusCode())
                    .addEvidence("pageParameter", page)
                    .addEvidence("calculatedOffset", (long) page * 50) // Assuming default limit of 50
                    .addRecommendation("Implement maximum page number limits (e.g., max 10000 pages)")
                    .addRecommendation("Return 400 Bad Request for page numbers exceeding maximum")
                    .addRecommendation("Use cursor-based pagination instead of offset-based for large datasets")
                    .addRecommendation("Add query timeouts to prevent long-running queries")
                    .addRecommendation("Monitor and alert on unusually high page parameter values")
                    .reproductionSteps(
                        "1. Send GET request to " + urlWithPage + "\n" +
                        "2. Include page=" + page + " parameter\n" +
                        "3. Observe server processes request without proper validation\n" +
                        "4. Database attempts to skip millions of records (OFFSET = page * limit)"
                    )
                    .build();

                return new ResourceTestResult(Optional.of(vulnerability), PAGINATION_TEST_PAGES.length);
            }
        }

        return new ResourceTestResult(Optional.empty(), PAGINATION_TEST_PAGES.length);
    }

    /**
     * Determine severity based on pagination limit.
     */
    private Severity determinePaginationSeverity(int limit) {
        if (limit >= 100000) {
            return Severity.HIGH;
        } else if (limit >= 10000) {
            return Severity.MEDIUM;
        } else {
            return Severity.LOW;
        }
    }

    /**
     * Determine severity based on page parameter value.
     */
    private Severity determinePageSeverity(int page) {
        if (page >= 100000 || page == Integer.MAX_VALUE) {
            return Severity.HIGH;
        } else if (page >= 10000) {
            return Severity.MEDIUM;
        } else {
            return Severity.LOW;
        }
    }

    /**
     * Result of a resource consumption test case.
     */
    private record ResourceTestResult(
        Optional<VulnerabilityReport> vulnerability,
        int testsExecuted
    ) {}
}
