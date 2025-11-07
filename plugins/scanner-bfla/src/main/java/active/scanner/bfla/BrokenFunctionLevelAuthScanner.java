package active.scanner.bfla;

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
 * Scanner for detecting Broken Function Level Authorization vulnerabilities.
 *
 * <p>Broken Function Level Authorization (BFLA) occurs when an application does not
 * properly enforce authorization checks on functions, allowing users to access
 * administrative or privileged functionality they should not have access to.
 *
 * <p>This scanner tests for:
 * <ul>
 *   <li>Access to administrative endpoints with regular user credentials</li>
 *   <li>HTTP method tampering to access privileged operations</li>
 *   <li>Path manipulation to access admin functions</li>
 *   <li>Role escalation through function access</li>
 *   <li>Missing authorization checks on sensitive operations</li>
 * </ul>
 *
 * <p>Based on OWASP API Security Top 10 - API5:2023
 */
public final class BrokenFunctionLevelAuthScanner extends AbstractScanner {
    private static final String SCANNER_ID = "broken-function-level-auth-scanner";
    private static final String SCANNER_NAME = "Broken Function Level Authorization Scanner";
    private static final String SCANNER_DESCRIPTION =
        "Detects broken function level authorization including unauthorized access to admin functions and privilege escalation";

    // Common administrative path patterns
    private static final List<String> ADMIN_PATH_PATTERNS = List.of(
        "/admin", "/administrator", "/management", "/manage",
        "/console", "/dashboard", "/settings", "/config",
        "/superuser", "/moderator", "/internal", "/private"
    );

    // Privileged HTTP methods that typically require higher permissions
    private static final List<String> PRIVILEGED_METHODS = List.of(
        "DELETE", "PUT", "PATCH"
    );

    public BrokenFunctionLevelAuthScanner() {
        super();
    }

    public BrokenFunctionLevelAuthScanner(ScannerConfig config) {
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
        return List.of(VulnerabilityReport.VulnerabilityType.BFLA);
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        String path = endpoint.getPath().toLowerCase();

        // Skip obvious public endpoints
        if (path.contains("/health") ||
            path.contains("/status") ||
            path.contains("/ping") ||
            path.equals("/") ||
            path.equals("/api")) {
            return false;
        }

        // This scanner is most relevant for:
        // 1. Any endpoint that might have admin variants
        // 2. Endpoints with sensitive operations
        // 3. Endpoints that modify data
        return true;
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int totalTests = 0;

        // Test Case 1: Access to administrative path variants
        BflaTestResult adminPathTest = testAdministrativePathAccess(endpoint, httpClient, context);
        totalTests += adminPathTest.testsExecuted();
        adminPathTest.vulnerability().ifPresent(vulnerabilities::add);

        // Test Case 2: HTTP method tampering
        BflaTestResult methodTamperTest = testHttpMethodTampering(endpoint, httpClient, context);
        totalTests += methodTamperTest.testsExecuted();
        methodTamperTest.vulnerability().ifPresent(vulnerabilities::add);

        // Test Case 3: Privileged method access on regular endpoints
        if (!PRIVILEGED_METHODS.contains(endpoint.getMethod())) {
            BflaTestResult privilegedMethodTest = testPrivilegedMethodAccess(endpoint, httpClient, context);
            totalTests += privilegedMethodTest.testsExecuted();
            privilegedMethodTest.vulnerability().ifPresent(vulnerabilities::add);
        }

        // Test Case 4: Admin function guessing
        BflaTestResult adminFunctionTest = testAdminFunctionGuessing(endpoint, httpClient, context);
        totalTests += adminFunctionTest.testsExecuted();
        adminFunctionTest.vulnerability().ifPresent(vulnerabilities::add);

        return createSuccessResult(endpoint, vulnerabilities, totalTests, startTime);
    }

    /**
     * Test access to administrative path variants of the endpoint.
     * For example, if endpoint is /api/users, try /api/admin/users, /api/users/admin, etc.
     */
    private BflaTestResult testAdministrativePathAccess(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing administrative path access for: " + endpoint);

        String originalPath = endpoint.getPath();
        int testsExecuted = 0;

        // Generate administrative path variants
        List<String> adminVariants = generateAdminPathVariants(originalPath);

        for (String adminPath : adminVariants) {
            String url = context.buildUrl(adminPath);

            TestRequest request = TestRequest.builder()
                .url(url)
                .method(endpoint.getMethod())
                .headers(context.getAuthHeaders())
                .build();

            TestResponse response = executeTest(httpClient, request, "Admin Path: " + adminPath);
            testsExecuted++;

            // If we can access an admin path, it's a vulnerability
            if (isSuccessfulUnauthorizedAccess(response)) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.BFLA)
                    .severity(Severity.HIGH)
                    .endpoint(endpoint)
                    .title("Unauthorized Access to Administrative Function")
                    .description(
                        "Successfully accessed administrative endpoint variant '" + adminPath + "' " +
                        "which should be restricted to administrative users only. " +
                        "The application does not properly enforce function-level authorization, " +
                        "allowing regular users to access privileged administrative functions."
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("originalPath", originalPath)
                    .addEvidence("adminPath", adminPath)
                    .addEvidence("statusCode", response.getStatusCode())
                    .addEvidence("method", endpoint.getMethod())
                    .addRecommendation("Implement role-based access control (RBAC) for all administrative functions")
                    .addRecommendation("Verify user roles/permissions before executing privileged operations")
                    .addRecommendation("Return 403 Forbidden for unauthorized function access attempts")
                    .addRecommendation("Use a centralized authorization framework")
                    .addRecommendation("Follow principle of least privilege")
                    .reproductionSteps(
                        "1. Authenticate with regular user credentials\n" +
                        "2. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                        "3. Observe " + response.getStatusCode() + " response (expected 403 Forbidden for non-admin users)"
                    )
                    .build();

                return new BflaTestResult(Optional.of(vulnerability), testsExecuted);
            }
        }

        return new BflaTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Test HTTP method tampering to access privileged operations.
     * For example, if GET is allowed, try PUT/DELETE which might be allowed without proper checks.
     */
    private BflaTestResult testHttpMethodTampering(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing HTTP method tampering for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());
        int testsExecuted = 0;

        // Test privileged methods that shouldn't be accessible
        for (String privilegedMethod : PRIVILEGED_METHODS) {
            // Skip if this is already the endpoint's method
            if (privilegedMethod.equals(endpoint.getMethod())) {
                continue;
            }

            TestRequest request = TestRequest.builder()
                .url(url)
                .method(privilegedMethod)
                .headers(context.getAuthHeaders())
                .build();

            TestResponse response = executeTest(httpClient, request, "Method Tampering: " + privilegedMethod);
            testsExecuted++;

            // If privileged method is accepted when it shouldn't be
            if (isSuccessfulUnauthorizedAccess(response)) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.BFLA)
                    .severity(determineSeverityByMethod(privilegedMethod))
                    .endpoint(endpoint)
                    .title("HTTP Method Tampering Allows Privileged Operations")
                    .description(
                        "The endpoint accepts privileged HTTP method '" + privilegedMethod + "' " +
                        "when the documented/expected method is '" + endpoint.getMethod() + "'. " +
                        "This allows users to perform privileged operations (modification/deletion) " +
                        "without proper authorization checks."
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("originalMethod", endpoint.getMethod())
                    .addEvidence("privilegedMethod", privilegedMethod)
                    .addEvidence("statusCode", response.getStatusCode())
                    .addRecommendation("Implement method-level authorization checks")
                    .addRecommendation("Explicitly whitelist allowed HTTP methods per endpoint")
                    .addRecommendation("Return 405 Method Not Allowed for unsupported methods")
                    .addRecommendation("Verify permissions match the operation being performed")
                    .reproductionSteps(
                        "1. Send " + privilegedMethod + " request to " + url + "\n" +
                        "2. Observe " + response.getStatusCode() + " response\n" +
                        "3. Operation succeeds despite lack of authorization for privileged method"
                    )
                    .build();

                return new BflaTestResult(Optional.of(vulnerability), testsExecuted);
            }
        }

        return new BflaTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Test if regular endpoints accept privileged methods without authorization.
     */
    private BflaTestResult testPrivilegedMethodAccess(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing privileged method access for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        // Test DELETE method which should typically require admin privileges
        TestRequest deleteRequest = TestRequest.builder()
            .url(url)
            .method("DELETE")
            .headers(context.getAuthHeaders())
            .build();

        TestResponse deleteResponse = executeTest(httpClient, deleteRequest, "Privileged DELETE");

        if (isSuccessfulUnauthorizedAccess(deleteResponse)) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.BFLA)
                .severity(Severity.CRITICAL)
                .endpoint(endpoint)
                .title("Unauthorized DELETE Operation Allowed")
                .description(
                    "The endpoint allows DELETE operations without proper authorization checks. " +
                    "DELETE is a privileged operation that should typically require administrative " +
                    "permissions, but it was executed successfully with regular user credentials."
                )
                .exploitRequest(deleteRequest)
                .exploitResponse(deleteResponse)
                .addEvidence("statusCode", deleteResponse.getStatusCode())
                .addRecommendation("Implement strict authorization for DELETE operations")
                .addRecommendation("Require admin role verification for destructive operations")
                .addRecommendation("Log and audit all DELETE operations")
                .addRecommendation("Consider implementing soft deletes instead of hard deletes")
                .reproductionSteps(
                    "1. Send DELETE request to " + url + " with regular user credentials\n" +
                    "2. Observe " + deleteResponse.getStatusCode() + " response\n" +
                    "3. DELETE operation succeeds without admin authorization"
                )
                .build();

            return new BflaTestResult(Optional.of(vulnerability), 1);
        }

        return new BflaTestResult(Optional.empty(), 1);
    }

    /**
     * Test common administrative function naming patterns.
     */
    private BflaTestResult testAdminFunctionGuessing(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing admin function guessing for: " + endpoint);

        String path = endpoint.getPath();
        int testsExecuted = 0;

        // Generate potential admin function names
        List<String> adminFunctions = generateAdminFunctionNames(path);

        for (String adminFunction : adminFunctions) {
            String url = context.buildUrl(adminFunction);

            TestRequest request = TestRequest.builder()
                .url(url)
                .method(endpoint.getMethod())
                .headers(context.getAuthHeaders())
                .build();

            TestResponse response = executeTest(httpClient, request, "Admin Function: " + adminFunction);
            testsExecuted++;

            if (isSuccessfulUnauthorizedAccess(response)) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.BFLA)
                    .severity(Severity.HIGH)
                    .endpoint(endpoint)
                    .title("Predictable Administrative Function Accessible")
                    .description(
                        "Discovered accessible administrative function '" + adminFunction + "' " +
                        "through predictable naming patterns. This function should be restricted " +
                        "to administrators but is accessible with regular user credentials."
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("discoveredFunction", adminFunction)
                    .addEvidence("statusCode", response.getStatusCode())
                    .addRecommendation("Implement authorization checks on all administrative functions")
                    .addRecommendation("Avoid predictable naming patterns for sensitive functions")
                    .addRecommendation("Use security through proper design, not obscurity")
                    .addRecommendation("Implement deny-by-default access control")
                    .reproductionSteps(
                        "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                        "2. Observe " + response.getStatusCode() + " response\n" +
                        "3. Administrative function is accessible without admin privileges"
                    )
                    .build();

                return new BflaTestResult(Optional.of(vulnerability), testsExecuted);
            }
        }

        return new BflaTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Generate administrative path variants for testing.
     */
    private List<String> generateAdminPathVariants(String originalPath) {
        List<String> variants = new ArrayList<>();

        // Remove leading/trailing slashes for easier manipulation
        String cleanPath = originalPath.replaceAll("^/+|/+$", "");
        String[] parts = cleanPath.split("/");

        for (String adminPattern : ADMIN_PATH_PATTERNS) {
            // Insert admin pattern at different positions
            if (parts.length > 0) {
                // Add admin prefix: /admin/api/users
                variants.add("/" + adminPattern.substring(1) + "/" + cleanPath);

                // Add admin after first segment: /api/admin/users
                if (parts.length >= 2) {
                    variants.add("/" + parts[0] + adminPattern + "/" + String.join("/", Arrays.copyOfRange(parts, 1, parts.length)));
                }

                // Add admin suffix: /api/users/admin
                variants.add("/" + cleanPath + adminPattern);
            }
        }

        return variants.stream().distinct().limit(10).toList(); // Limit to avoid too many requests
    }

    /**
     * Generate potential admin function names based on the original path.
     */
    private List<String> generateAdminFunctionNames(String originalPath) {
        List<String> functions = new ArrayList<>();

        String basePath = originalPath;
        if (basePath.endsWith("/")) {
            basePath = basePath.substring(0, basePath.length() - 1);
        }

        // Common admin function patterns
        functions.add(basePath + "/delete");
        functions.add(basePath + "/deleteAll");
        functions.add(basePath + "/export");
        functions.add(basePath + "/backup");
        functions.add(basePath + "/restore");
        functions.add(basePath + "/reset");
        functions.add(basePath + "/purge");
        functions.add(basePath + "/bulk");

        return functions.stream().distinct().limit(8).toList();
    }

    /**
     * Determine severity based on HTTP method.
     */
    private Severity determineSeverityByMethod(String method) {
        return switch (method) {
            case "DELETE" -> Severity.CRITICAL;
            case "PUT", "PATCH" -> Severity.HIGH;
            default -> Severity.MEDIUM;
        };
    }

    /**
     * Result of a BFLA test case.
     */
    private record BflaTestResult(
        Optional<VulnerabilityReport> vulnerability,
        int testsExecuted
    ) {}
}
