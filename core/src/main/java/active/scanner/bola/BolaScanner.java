package active.scanner.bola;

import active.http.HttpClient;
import active.model.ApiEndpoint;
import active.model.TestRequest;
import active.model.TestResponse;
import active.model.VulnerabilityReport;
import active.scanner.*;
import model.ParameterSpec;
import model.Severity;

import java.time.Instant;
import java.util.*;
import java.util.logging.Logger;

/**
 * Scanner for detecting Broken Object Level Authorization (BOLA) / IDOR vulnerabilities.
 *
 * <p>BOLA occurs when an application doesn't properly verify that a user is authorized
 * to access a specific object. This scanner tests for BOLA by:
 * <ul>
 *   <li>Identifying endpoints with object ID parameters</li>
 *   <li>Testing access to different object IDs</li>
 *   <li>Comparing authorized vs unauthorized access</li>
 *   <li>Detecting excessive data exposure</li>
 * </ul>
 *
 * <p>Based on OWASP API Security Top 10 - API1:2023
 */
public final class BolaScanner implements VulnerabilityScanner {
    private static final Logger logger = Logger.getLogger(BolaScanner.class.getName());

    private static final String SCANNER_ID = "bola-scanner";
    private static final String SCANNER_NAME = "BOLA/IDOR Scanner";
    private static final String SCANNER_DESCRIPTION =
        "Detects Broken Object Level Authorization (BOLA) and Insecure Direct Object Reference (IDOR) vulnerabilities";

    private ScannerConfig config;

    public BolaScanner() {
        this.config = ScannerConfig.defaultConfig();
    }

    public BolaScanner(ScannerConfig config) {
        this.config = config;
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
        return List.of(VulnerabilityReport.VulnerabilityType.BOLA);
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // BOLA is most relevant for endpoints with ID parameters
        // and data access operations (GET, PUT, DELETE, PATCH)
        String method = endpoint.getMethod();
        boolean isDataAccessMethod = method.equals("GET") ||
                                     method.equals("PUT") ||
                                     method.equals("DELETE") ||
                                     method.equals("PATCH");

        if (!isDataAccessMethod) {
            return false;
        }

        // Check if endpoint has ID-like parameters in path
        return hasIdParameter(endpoint);
    }

    @Override
    public ScanResult scan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int totalTests = 0;
        int failedTests = 0;

        try {
            logger.info("Starting BOLA scan on: " + endpoint);

            // Test Case 1: Unauthenticated access to resources
            BolaTestResult unauthTest = testUnauthenticatedAccess(endpoint, httpClient, context);
            totalTests += unauthTest.testsExecuted();
            if (unauthTest.vulnerability().isPresent()) {
                vulnerabilities.add(unauthTest.vulnerability().get());
            }

            // Test Case 2: Sequential ID enumeration
            BolaTestResult enumTest = testIdEnumeration(endpoint, httpClient, context);
            totalTests += enumTest.testsExecuted();
            if (enumTest.vulnerability().isPresent()) {
                vulnerabilities.add(enumTest.vulnerability().get());
            }

            // Test Case 3: Horizontal privilege escalation
            if (context.getAuthHeaders() != null && !context.getAuthHeaders().isEmpty()) {
                BolaTestResult horizTest = testHorizontalPrivilegeEscalation(endpoint, httpClient, context);
                totalTests += horizTest.testsExecuted();
                if (horizTest.vulnerability().isPresent()) {
                    vulnerabilities.add(horizTest.vulnerability().get());
                }
            }

            ScanResult.ScanStatus status = vulnerabilities.isEmpty()
                ? ScanResult.ScanStatus.SUCCESS
                : ScanResult.ScanStatus.SUCCESS;

            return ScanResult.builder()
                .scannerId(SCANNER_ID)
                .endpoint(endpoint)
                .status(status)
                .vulnerabilities(vulnerabilities)
                .totalTests(totalTests)
                .failedTests(failedTests)
                .startTime(startTime)
                .endTime(Instant.now())
                .build();

        } catch (Exception e) {
            logger.warning("BOLA scan failed for " + endpoint + ": " + e.getMessage());

            return ScanResult.builder()
                .scannerId(SCANNER_ID)
                .endpoint(endpoint)
                .status(ScanResult.ScanStatus.FAILED)
                .totalTests(totalTests)
                .failedTests(totalTests)
                .startTime(startTime)
                .endTime(Instant.now())
                .errorMessage("Scan failed: " + e.getMessage())
                .build();
        }
    }

    @Override
    public ScannerConfig getConfig() {
        return config;
    }

    @Override
    public void setConfig(ScannerConfig config) {
        this.config = config;
    }

    /**
     * Test if resources can be accessed without authentication.
     */
    private BolaTestResult testUnauthenticatedAccess(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing unauthenticated access for: " + endpoint);

        // Try accessing with common ID values without authentication
        List<String> testIds = List.of("1", "2", "100");
        int testsExecuted = 0;

        for (String testId : testIds) {
            String url = buildUrlWithId(endpoint, testId, context);

            TestRequest request = TestRequest.builder()
                .url(url)
                .method(endpoint.getMethod())
                .build();

            TestResponse response = httpClient.execute(request);
            testsExecuted++;

            // If we get 200 OK without auth, it's a vulnerability
            if (response.getStatusCode() == 200) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.BOLA)
                    .severity(Severity.HIGH)
                    .endpoint(endpoint)
                    .title("Unauthenticated Access to Protected Resource")
                    .description(
                        "The endpoint allows access to resources without authentication. " +
                        "Resource with ID '" + testId + "' was accessible without credentials."
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("testId", testId)
                    .addEvidence("statusCode", response.getStatusCode())
                    .addEvidence("responseSize", response.getBody() != null ? response.getBody().length() : 0)
                    .addRecommendation("Implement proper authentication checks before allowing access to resources")
                    .addRecommendation("Return 401 Unauthorized for requests without valid credentials")
                    .addRecommendation("Ensure all object access goes through authorization middleware")
                    .reproductionSteps(
                        "1. Send " + endpoint.getMethod() + " request to " + url + " without authentication\n" +
                        "2. Observe 200 OK response with resource data"
                    )
                    .build();

                return new BolaTestResult(Optional.of(vulnerability), testsExecuted);
            }
        }

        return new BolaTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Test if sequential IDs can be enumerated to access other users' data.
     */
    private BolaTestResult testIdEnumeration(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing ID enumeration for: " + endpoint);

        // Test with authentication if available
        Map<String, String> headers = new HashMap<>(context.getAuthHeaders());

        // Test sequential IDs
        List<Integer> testIds = List.of(1, 2, 3, 4, 5, 10, 100, 999);
        int successfulAccesses = 0;
        int testsExecuted = 0;
        List<Integer> accessibleIds = new ArrayList<>();

        for (Integer testId : testIds) {
            String url = buildUrlWithId(endpoint, testId.toString(), context);

            TestRequest request = TestRequest.builder()
                .url(url)
                .method(endpoint.getMethod())
                .headers(headers)
                .build();

            TestResponse response = httpClient.execute(request);
            testsExecuted++;

            if (response.getStatusCode() == 200) {
                successfulAccesses++;
                accessibleIds.add(testId);
            }
        }

        // If we can access multiple sequential IDs, it's likely a BOLA vulnerability
        if (successfulAccesses >= 3) {
            String url = buildUrlWithId(endpoint, "{id}", context);

            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.BOLA)
                .severity(Severity.HIGH)
                .endpoint(endpoint)
                .title("Broken Object Level Authorization - ID Enumeration")
                .description(
                    "The endpoint allows enumeration of object IDs without proper authorization checks. " +
                    "Successfully accessed " + successfulAccesses + " different resources by incrementing IDs. " +
                    "This allows attackers to access other users' data by guessing or enumerating IDs."
                )
                .addEvidence("successfulAccesses", successfulAccesses)
                .addEvidence("totalTests", testsExecuted)
                .addEvidence("accessibleIds", accessibleIds.toString())
                .addRecommendation("Implement object-level authorization checks for each resource access")
                .addRecommendation("Verify that the authenticated user has permission to access the specific object ID")
                .addRecommendation("Use non-sequential, non-guessable UUIDs instead of incremental IDs")
                .addRecommendation("Return 403 Forbidden for unauthorized access attempts, not 404")
                .reproductionSteps(
                    "1. Authenticate as a user\n" +
                    "2. Access " + url + " with IDs: " + accessibleIds + "\n" +
                    "3. Observe that all IDs are accessible without ownership verification"
                )
                .build();

            return new BolaTestResult(Optional.of(vulnerability), testsExecuted);
        }

        return new BolaTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Test for horizontal privilege escalation (accessing other users' resources).
     */
    private BolaTestResult testHorizontalPrivilegeEscalation(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing horizontal privilege escalation for: " + endpoint);

        // This test would ideally use multiple user credentials
        // For now, we'll test if the endpoint validates object ownership

        Map<String, String> headers = new HashMap<>(context.getAuthHeaders());

        // Test accessing resources that likely belong to other users
        List<String> otherUserIds = List.of("999", "1000", "9999");
        int testsExecuted = 0;

        for (String otherId : otherUserIds) {
            String url = buildUrlWithId(endpoint, otherId, context);

            TestRequest request = TestRequest.builder()
                .url(url)
                .method(endpoint.getMethod())
                .headers(headers)
                .build();

            TestResponse response = httpClient.execute(request);
            testsExecuted++;

            // If we get 200 OK for what should be another user's resource, it's vulnerable
            if (response.getStatusCode() == 200 && response.getBody() != null) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.BOLA)
                    .severity(Severity.CRITICAL)
                    .endpoint(endpoint)
                    .title("Horizontal Privilege Escalation - BOLA")
                    .description(
                        "The endpoint allows authenticated users to access resources belonging to other users. " +
                        "Successfully accessed resource with ID '" + otherId + "' which likely belongs to another user."
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("targetId", otherId)
                    .addEvidence("statusCode", response.getStatusCode())
                    .addRecommendation("Implement strict object-level authorization checks")
                    .addRecommendation("Verify resource ownership before granting access")
                    .addRecommendation("Use attribute-based access control (ABAC) or role-based access control (RBAC)")
                    .reproductionSteps(
                        "1. Authenticate as User A\n" +
                        "2. Access " + url + " (resource belonging to User B)\n" +
                        "3. Observe successful access to another user's resource"
                    )
                    .build();

                return new BolaTestResult(Optional.of(vulnerability), testsExecuted);
            }
        }

        return new BolaTestResult(Optional.empty(), testsExecuted);
    }

    private boolean hasIdParameter(ApiEndpoint endpoint) {
        // Check for path parameters that look like IDs
        for (ParameterSpec param : endpoint.getPathParameters()) {
            String name = param.getName().toLowerCase();
            if (name.equals("id") ||
                name.endsWith("id") ||
                name.equals("userid") ||
                name.equals("objectid")) {
                return true;
            }
        }

        // Also check if the path contains {id} pattern
        String path = endpoint.getPath().toLowerCase();
        return path.contains("{id}") ||
               path.contains("/{id}") ||
               path.matches(".*\\{\\w*id\\}.*");
    }

    private String buildUrlWithId(ApiEndpoint endpoint, String idValue, ScanContext context) {
        String path = endpoint.getPath();

        // Replace path parameter placeholders with actual ID value
        // Support both {id} and {userId} style parameters
        path = path.replaceAll("\\{id\\}", idValue);
        path = path.replaceAll("\\{\\w*[iI][dD]\\}", idValue);

        return context.buildUrl(path);
    }

    /**
     * Result of a BOLA test case.
     */
    private record BolaTestResult(
        Optional<VulnerabilityReport> vulnerability,
        int testsExecuted
    ) {}
}
