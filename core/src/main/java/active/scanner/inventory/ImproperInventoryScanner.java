package active.scanner.inventory;

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
 * Scanner for detecting Improper Inventory Management vulnerabilities.
 *
 * <p>Improper Inventory Management occurs when organizations fail to properly track
 * their API inventory, leading to security risks from undocumented, deprecated, or
 * zombie APIs that remain accessible.
 *
 * <p>This scanner tests for:
 * <ul>
 *   <li>Missing or outdated API version information</li>
 *   <li>Lack of version deprecation notices</li>
 *   <li>Missing API documentation headers/metadata</li>
 *   <li>Undocumented endpoints (lack of OpenAPI/Swagger)</li>
 *   <li>Old API versions still accessible without warnings</li>
 *   <li>Missing inventory metadata (environment, owner, etc.)</li>
 * </ul>
 *
 * <p>Based on OWASP API Security Top 10 - API9:2023
 */
public final class ImproperInventoryScanner extends AbstractScanner {
    private static final String SCANNER_ID = "improper-inventory-scanner";
    private static final String SCANNER_NAME = "Improper Inventory Management Scanner";
    private static final String SCANNER_DESCRIPTION =
        "Detects improper API inventory management including missing versioning, documentation, and lifecycle metadata";

    // Version patterns in URL paths
    private static final Pattern VERSION_PATTERN = Pattern.compile("/v\\d+/|/api/\\d+/|/version/\\d+/");

    // Deprecated version numbers that should show warnings
    private static final List<String> POTENTIALLY_DEPRECATED_VERSIONS = List.of(
        "v1", "v0", "api/1", "version/1"
    );

    // Headers indicating API documentation/metadata
    private static final List<String> DOCUMENTATION_HEADERS = List.of(
        "API-Documentation",
        "API-Docs",
        "X-API-Documentation",
        "Link"
    );

    // Headers indicating API lifecycle
    private static final List<String> LIFECYCLE_HEADERS = List.of(
        "X-API-Version",
        "API-Version",
        "X-API-Deprecated",
        "Deprecation",
        "Sunset",
        "X-API-Status"
    );

    public ImproperInventoryScanner() {
        super();
    }

    public ImproperInventoryScanner(ScannerConfig config) {
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
        return List.of(VulnerabilityReport.VulnerabilityType.IMPROPER_INVENTORY);
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // This scanner is applicable to all endpoints
        return true;
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int totalTests = 0;

        // Test Case 1: Missing version information
        InventoryTestResult versionTest = testVersionInformation(endpoint, httpClient, context);
        totalTests += versionTest.testsExecuted();
        vulnerabilities.addAll(versionTest.vulnerabilities());

        // Test Case 2: Missing deprecation warnings
        InventoryTestResult deprecationTest = testDeprecationWarnings(endpoint, httpClient, context);
        totalTests += deprecationTest.testsExecuted();
        vulnerabilities.addAll(deprecationTest.vulnerabilities());

        // Test Case 3: Missing documentation metadata
        InventoryTestResult documentationTest = testDocumentationMetadata(endpoint, httpClient, context);
        totalTests += documentationTest.testsExecuted();
        vulnerabilities.addAll(documentationTest.vulnerabilities());

        // Test Case 4: Missing lifecycle headers
        InventoryTestResult lifecycleTest = testLifecycleHeaders(endpoint, httpClient, context);
        totalTests += lifecycleTest.testsExecuted();
        vulnerabilities.addAll(lifecycleTest.vulnerabilities());

        // Test Case 5: Old version accessibility
        if (hasVersionInPath(endpoint.getPath())) {
            InventoryTestResult oldVersionTest = testOldVersionAccess(endpoint, httpClient, context);
            totalTests += oldVersionTest.testsExecuted();
            vulnerabilities.addAll(oldVersionTest.vulnerabilities());
        }

        return createSuccessResult(endpoint, vulnerabilities, totalTests, startTime);
    }

    /**
     * Test for missing version information.
     */
    private InventoryTestResult testVersionInformation(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing version information for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Version Information Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();

        // Check for version in path
        boolean hasVersionInPath = hasVersionInPath(endpoint.getPath());

        // Check for version in headers
        String apiVersion = getHeader(response, "API-Version");
        String xApiVersion = getHeader(response, "X-API-Version");

        boolean hasVersionHeader = apiVersion != null || xApiVersion != null;

        if (!hasVersionInPath && !hasVersionHeader) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.IMPROPER_INVENTORY)
                .severity(Severity.MEDIUM)
                .endpoint(endpoint)
                .title("Missing API Version Information")
                .description(
                    "The API endpoint does not expose version information in the URL path or headers. " +
                    "Without proper versioning, it's difficult to track API lifecycle, manage deprecations, " +
                    "and maintain an accurate inventory of deployed APIs. This can lead to zombie APIs " +
                    "remaining in production without proper oversight."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("versionInPath", false)
                .addEvidence("versionInHeaders", false)
                .addRecommendation("Add version information to API path (e.g., /v1/, /v2/)")
                .addRecommendation("Include API-Version or X-API-Version header in responses")
                .addRecommendation("Implement API versioning strategy across all endpoints")
                .addRecommendation("Document all API versions in central inventory")
                .reproductionSteps(
                    "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                    "2. Check response headers for API-Version or X-API-Version\n" +
                    "3. Check URL path for version indicator\n" +
                    "4. No version information found"
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        return new InventoryTestResult(vulnerabilities, 1);
    }

    /**
     * Test for missing deprecation warnings on old versions.
     */
    private InventoryTestResult testDeprecationWarnings(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing deprecation warnings for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());
        String path = endpoint.getPath().toLowerCase();

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Deprecation Warning Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();

        // Check if this is potentially an old version
        boolean isPotentiallyOldVersion = POTENTIALLY_DEPRECATED_VERSIONS.stream()
            .anyMatch(path::contains);

        if (isPotentiallyOldVersion) {
            String deprecation = getHeader(response, "Deprecation");
            String sunset = getHeader(response, "Sunset");
            String xApiDeprecated = getHeader(response, "X-API-Deprecated");
            String warningHeader = getHeader(response, "Warning");

            boolean hasDeprecationInfo = deprecation != null || sunset != null ||
                                        xApiDeprecated != null ||
                                        (warningHeader != null && warningHeader.toLowerCase().contains("deprecat"));

            if (!hasDeprecationInfo) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.IMPROPER_INVENTORY)
                    .severity(Severity.MEDIUM)
                    .endpoint(endpoint)
                    .title("Missing Deprecation Warnings on Potentially Old API Version")
                    .description(
                        "The endpoint appears to be an older API version but lacks deprecation warnings. " +
                        "Without proper deprecation notices (Deprecation, Sunset, or Warning headers), " +
                        "API consumers cannot prepare for version retirement, and old versions may become " +
                        "zombie APIs with security vulnerabilities that are no longer maintained."
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("potentiallyOldVersion", true)
                    .addEvidence("path", endpoint.getPath())
                    .addEvidence("hasDeprecationHeaders", false)
                    .addRecommendation("Add Deprecation: true header for deprecated versions")
                    .addRecommendation("Add Sunset header with end-of-life date (RFC 8594)")
                    .addRecommendation("Include Warning header with deprecation message")
                    .addRecommendation("Document version lifecycle in API inventory")
                    .addRecommendation("Implement sunset period for old API versions")
                    .reproductionSteps(
                        "1. Send request to " + url + "\n" +
                        "2. Check response headers for Deprecation, Sunset, or Warning\n" +
                        "3. No deprecation information found for old version"
                    )
                    .build();

                vulnerabilities.add(vulnerability);
            }
        }

        return new InventoryTestResult(vulnerabilities, 1);
    }

    /**
     * Test for missing documentation metadata.
     */
    private InventoryTestResult testDocumentationMetadata(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing documentation metadata for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Documentation Metadata Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();

        // Check for documentation headers
        boolean hasDocumentationHeader = DOCUMENTATION_HEADERS.stream()
            .anyMatch(header -> getHeader(response, header) != null);

        // Check for Link header with documentation
        String linkHeader = getHeader(response, "Link");
        boolean hasDocLink = linkHeader != null &&
            (linkHeader.contains("rel=\"documentation\"") ||
             linkHeader.contains("rel=\"describedby\"") ||
             linkHeader.contains("swagger") ||
             linkHeader.contains("openapi"));

        if (!hasDocumentationHeader && !hasDocLink) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.IMPROPER_INVENTORY)
                .severity(Severity.LOW)
                .endpoint(endpoint)
                .title("Missing API Documentation Metadata")
                .description(
                    "The API does not expose documentation metadata in response headers. " +
                    "Best practices include providing documentation links via headers to help " +
                    "maintain API inventory and ensure all endpoints are properly documented. " +
                    "Undocumented APIs are harder to track and may become shadow or zombie APIs."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("hasDocumentationHeaders", false)
                .addEvidence("hasLinkToDocumentation", false)
                .addRecommendation("Add Link header with rel=\"documentation\" to OpenAPI/Swagger spec")
                .addRecommendation("Include X-API-Documentation header with docs URL")
                .addRecommendation("Maintain central API catalog with all endpoints")
                .addRecommendation("Implement automated API discovery and documentation")
                .reproductionSteps(
                    "1. Send request to " + url + "\n" +
                    "2. Check response headers for documentation links\n" +
                    "3. No documentation metadata found"
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        return new InventoryTestResult(vulnerabilities, 1);
    }

    /**
     * Test for missing lifecycle headers.
     */
    private InventoryTestResult testLifecycleHeaders(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing lifecycle headers for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Lifecycle Headers Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();

        // Check for any lifecycle headers
        boolean hasLifecycleHeader = LIFECYCLE_HEADERS.stream()
            .anyMatch(header -> getHeader(response, header) != null);

        if (!hasLifecycleHeader) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.IMPROPER_INVENTORY)
                .severity(Severity.LOW)
                .endpoint(endpoint)
                .title("Missing API Lifecycle Metadata")
                .description(
                    "The API does not expose lifecycle metadata in response headers. " +
                    "Lifecycle headers (X-API-Version, X-API-Status, etc.) help track API maturity, " +
                    "status, and versioning information crucial for maintaining accurate API inventory. " +
                    "Without this metadata, it's difficult to identify which APIs are production-ready, " +
                    "deprecated, or experimental."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("hasLifecycleHeaders", false)
                .addRecommendation("Add X-API-Version header to indicate current version")
                .addRecommendation("Add X-API-Status header (e.g., stable, beta, deprecated)")
                .addRecommendation("Include metadata about API lifecycle stage")
                .addRecommendation("Implement API governance process with lifecycle tracking")
                .reproductionSteps(
                    "1. Send request to " + url + "\n" +
                    "2. Check response headers for lifecycle metadata\n" +
                    "3. No lifecycle information found"
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        return new InventoryTestResult(vulnerabilities, 1);
    }

    /**
     * Test if old API versions are still accessible without proper controls.
     */
    private InventoryTestResult testOldVersionAccess(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing old version accessibility for: " + endpoint);

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int testsExecuted = 0;

        // Try to access older versions if current version is detected
        String currentPath = endpoint.getPath();

        // Extract current version and try v1 if current is v2 or higher
        if (currentPath.contains("/v2/") || currentPath.contains("/v3/") ||
            currentPath.contains("/v4/") || currentPath.contains("/v5/")) {

            String v1Path = currentPath.replaceAll("/v[2-9]/", "/v1/");
            String url = context.buildUrl(v1Path);

            TestRequest request = TestRequest.builder()
                .url(url)
                .method(endpoint.getMethod())
                .headers(context.getAuthHeaders())
                .build();

            TestResponse response = executeTest(httpClient, request, "Old Version Access Check");
            testsExecuted++;

            // If old version is accessible
            if (response.getStatusCode() >= 200 && response.getStatusCode() < 300) {
                String warningHeader = getHeader(response, "Warning");
                String deprecationHeader = getHeader(response, "Deprecation");

                boolean hasWarnings = warningHeader != null || deprecationHeader != null;

                if (!hasWarnings) {
                    VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                        .type(VulnerabilityReport.VulnerabilityType.IMPROPER_INVENTORY)
                        .severity(Severity.HIGH)
                        .endpoint(endpoint)
                        .title("Old API Version Accessible Without Deprecation Warnings")
                        .description(
                            "An older API version (/v1/) is still accessible without deprecation warnings " +
                            "while newer versions exist. This indicates poor API inventory management. " +
                            "Old versions may contain unpatched vulnerabilities, lack modern security controls, " +
                            "and become zombie APIs that are forgotten but remain exploitable."
                        )
                        .exploitRequest(request)
                        .exploitResponse(response)
                        .addEvidence("oldVersionPath", v1Path)
                        .addEvidence("currentVersionPath", currentPath)
                        .addEvidence("oldVersionAccessible", true)
                        .addEvidence("hasDeprecationWarnings", false)
                        .addRecommendation("Add deprecation warnings to old API versions")
                        .addRecommendation("Implement sunset policy for API versions")
                        .addRecommendation("Redirect old versions to current with 301 or return 410 Gone")
                        .addRecommendation("Maintain API version inventory with status tracking")
                        .addRecommendation("Regularly audit and retire old API versions")
                        .reproductionSteps(
                            "1. Current API path: " + currentPath + "\n" +
                            "2. Access old version: " + v1Path + "\n" +
                            "3. Old version returns " + response.getStatusCode() + " without warnings\n" +
                            "4. Zombie API version remains accessible"
                        )
                        .build();

                    vulnerabilities.add(vulnerability);
                }
            }
        }

        return new InventoryTestResult(vulnerabilities, testsExecuted);
    }

    /**
     * Check if path contains version information.
     */
    private boolean hasVersionInPath(String path) {
        return VERSION_PATTERN.matcher(path).find();
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
     * Result of an inventory management test case.
     */
    private record InventoryTestResult(
        List<VulnerabilityReport> vulnerabilities,
        int testsExecuted
    ) {}
}
