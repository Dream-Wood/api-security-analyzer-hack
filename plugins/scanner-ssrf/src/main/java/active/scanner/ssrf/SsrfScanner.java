package active.scanner.ssrf;

import active.http.HttpClient;
import active.model.ApiEndpoint;
import active.model.TestRequest;
import active.model.TestResponse;
import active.model.VulnerabilityReport;
import active.scanner.AbstractScanner;
import active.scanner.ScanContext;
import active.scanner.ScanResult;
import active.scanner.ScannerConfig;
import model.ParameterSpec;
import model.Severity;

import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Scanner for detecting Server-Side Request Forgery (SSRF) vulnerabilities.
 *
 * <p>SSRF occurs when an application fetches a remote resource without validating
 * the user-supplied URL. This allows attackers to coerce the application to send
 * crafted requests to unexpected destinations, potentially accessing internal systems,
 * cloud metadata services, or other sensitive resources.
 *
 * <p>This scanner tests for:
 * <ul>
 *   <li>URL parameter injection to internal/private IPs</li>
 *   <li>Access to cloud metadata services (AWS, Azure, GCP)</li>
 *   <li>Protocol smuggling (file://, dict://, gopher://, etc.)</li>
 *   <li>DNS rebinding and localhost bypasses</li>
 *   <li>URL parameter manipulation to reach internal services</li>
 * </ul>
 *
 * <p>Based on OWASP API Security Top 10 - API7:2023
 */
public final class SsrfScanner extends AbstractScanner {
    private static final String SCANNER_ID = "ssrf-scanner";
    private static final String SCANNER_NAME = "Server-Side Request Forgery (SSRF) Scanner";
    private static final String SCANNER_DESCRIPTION =
        "Detects SSRF vulnerabilities including internal network access and cloud metadata exposure";

    // Cloud metadata endpoints
    private static final List<String> CLOUD_METADATA_URLS = List.of(
        "http://169.254.169.254/latest/meta-data/",  // AWS
        "http://169.254.169.254/metadata/v1/",       // Digital Ocean
        "http://metadata.google.internal/computeMetadata/v1/", // GCP
        "http://169.254.169.254/metadata/instance",  // Azure
        "http://100.100.100.200/latest/meta-data/"   // Alibaba Cloud
    );

    // Internal/private IP ranges
    private static final List<String> INTERNAL_IPS = List.of(
        "http://127.0.0.1:80",
        "http://localhost:80",
        "http://0.0.0.0:80",
        "http://10.0.0.1:80",
        "http://172.16.0.1:80",
        "http://192.168.1.1:80",
        "http://[::1]:80",
        "http://[0:0:0:0:0:0:0:1]:80"
    );

    // Dangerous protocols
    private static final List<String> DANGEROUS_PROTOCOLS = List.of(
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "dict://localhost:11211/stats",
        "gopher://localhost:80/_GET%20/%20HTTP/1.1",
        "ldap://localhost:389",
        "sftp://internal-server/"
    );

    // URL bypass techniques
    private static final List<String> BYPASS_TECHNIQUES = List.of(
        "http://127.1:80",                    // Decimal notation
        "http://0x7f.0x0.0x0.0x1:80",        // Hex notation
        "http://2130706433:80",               // Decimal IP
        "http://127.000.000.001:80",         // Padded zeros
        "http://localhost.127.0.0.1.nip.io:80" // DNS tricks
    );

    // Parameter names that might accept URLs
    private static final List<String> URL_PARAMETER_NAMES = List.of(
        "url", "uri", "link", "href", "redirect", "redirectUrl", "return",
        "returnTo", "next", "callback", "callbackUrl", "webhook", "webhookUrl",
        "fetch", "load", "download", "proxy", "api", "endpoint", "target",
        "destination", "source", "import", "export", "feed", "rss"
    );

    // Pattern to detect URL-like parameters in response
    private static final Pattern URL_REFLECTION_PATTERN = Pattern.compile(
        "https?://[a-zA-Z0-9.-]+(?::[0-9]+)?(?:/[^\\s]*)?",
        Pattern.CASE_INSENSITIVE
    );

    public SsrfScanner() {
        super();
    }

    public SsrfScanner(ScannerConfig config) {
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
        return List.of(VulnerabilityReport.VulnerabilityType.SSRF);
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // Skip obvious monitoring endpoints
        String path = endpoint.getPath().toLowerCase();
        if (path.contains("/health") ||
            path.contains("/status") ||
            path.contains("/ping") ||
            path.contains("/metrics")) {
            return false;
        }

        // Check if endpoint has URL-like parameters
        if (endpoint.getParameters() != null) {
            for (ParameterSpec param : endpoint.getParameters()) {
                String paramName = param.getName().toLowerCase();
                if (URL_PARAMETER_NAMES.stream().anyMatch(paramName::contains)) {
                    return true;
                }
            }
        }

        // Also applicable to endpoints that might process URLs
        return path.contains("fetch") || path.contains("import") ||
               path.contains("webhook") || path.contains("callback") ||
               path.contains("proxy") || path.contains("redirect");
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int totalTests = 0;

        // Get URL parameters
        List<ParameterSpec> urlParams = findUrlParameters(endpoint);

        if (!urlParams.isEmpty()) {
            // Test Case 1: Cloud metadata access
            SsrfTestResult cloudTest = testCloudMetadataAccess(endpoint, urlParams, httpClient, context);
            totalTests += cloudTest.testsExecuted();
            cloudTest.vulnerability().ifPresent(vulnerabilities::add);

            // Test Case 2: Internal network access
            SsrfTestResult internalTest = testInternalNetworkAccess(endpoint, urlParams, httpClient, context);
            totalTests += internalTest.testsExecuted();
            internalTest.vulnerability().ifPresent(vulnerabilities::add);

            // Test Case 3: Protocol smuggling
            SsrfTestResult protocolTest = testProtocolSmuggling(endpoint, urlParams, httpClient, context);
            totalTests += protocolTest.testsExecuted();
            protocolTest.vulnerability().ifPresent(vulnerabilities::add);

            // Test Case 4: Localhost bypass techniques
            SsrfTestResult bypassTest = testBypassTechniques(endpoint, urlParams, httpClient, context);
            totalTests += bypassTest.testsExecuted();
            bypassTest.vulnerability().ifPresent(vulnerabilities::add);
        }

        return createSuccessResult(endpoint, vulnerabilities, totalTests, startTime);
    }

    /**
     * Find parameters that might accept URL values.
     */
    private List<ParameterSpec> findUrlParameters(ApiEndpoint endpoint) {
        List<ParameterSpec> urlParams = new ArrayList<>();

        if (endpoint.getParameters() != null) {
            for (ParameterSpec param : endpoint.getParameters()) {
                String paramName = param.getName().toLowerCase();
                if (URL_PARAMETER_NAMES.stream().anyMatch(paramName::contains)) {
                    urlParams.add(param);
                }
            }
        }

        return urlParams;
    }

    /**
     * Test access to cloud metadata services.
     */
    private SsrfTestResult testCloudMetadataAccess(
        ApiEndpoint endpoint,
        List<ParameterSpec> urlParams,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing cloud metadata access for: " + endpoint);

        int testsExecuted = 0;

        for (ParameterSpec param : urlParams) {
            for (String metadataUrl : CLOUD_METADATA_URLS) {
                String url = buildUrlWithParameter(endpoint, param, metadataUrl, context);

                TestRequest request = TestRequest.builder()
                    .url(url)
                    .method(endpoint.getMethod())
                    .headers(context.getAuthHeaders())
                    .build();

                TestResponse response = executeTest(httpClient, request,
                    "Cloud Metadata: " + metadataUrl);
                testsExecuted++;

                // Check for successful SSRF
                if (isSsrfSuccessful(response, metadataUrl)) {
                    VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                        .type(VulnerabilityReport.VulnerabilityType.SSRF)
                        .severity(Severity.CRITICAL)
                        .endpoint(endpoint)
                        .title("SSRF to Cloud Metadata Service")
                        .description(
                            "Server-Side Request Forgery vulnerability allows access to cloud metadata service. " +
                            "By injecting '" + metadataUrl + "' into the '" + param.getName() + "' parameter, " +
                            "the application fetches and potentially exposes sensitive cloud instance metadata " +
                            "including IAM credentials, instance details, and security configurations."
                        )
                        .exploitRequest(request)
                        .exploitResponse(response)
                        .addEvidence("parameter", param.getName())
                        .addEvidence("injectedUrl", metadataUrl)
                        .addEvidence("statusCode", response.getStatusCode())
                        .addEvidence("responseLength", response.getBody().length())
                        .addRecommendation("Implement strict URL validation and whitelisting")
                        .addRecommendation("Block access to private IP ranges (RFC 1918)")
                        .addRecommendation("Block cloud metadata endpoints (169.254.169.254)")
                        .addRecommendation("Use network segmentation and firewall rules")
                        .addRecommendation("Disable unnecessary URL schemes (file://, gopher://, etc.)")
                        .addRecommendation("Implement DNS validation and prevent rebinding attacks")
                        .reproductionSteps(
                            "1. Send " + endpoint.getMethod() + " request to endpoint\n" +
                            "2. Set '" + param.getName() + "' parameter to: " + metadataUrl + "\n" +
                            "3. Observe response contains cloud metadata information\n" +
                            "4. This can expose IAM credentials and sensitive instance data"
                        )
                        .build();

                    return new SsrfTestResult(Optional.of(vulnerability), testsExecuted);
                }
            }
        }

        return new SsrfTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Test access to internal network resources.
     */
    private SsrfTestResult testInternalNetworkAccess(
        ApiEndpoint endpoint,
        List<ParameterSpec> urlParams,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing internal network access for: " + endpoint);

        int testsExecuted = 0;

        for (ParameterSpec param : urlParams) {
            for (String internalIp : INTERNAL_IPS) {
                String url = buildUrlWithParameter(endpoint, param, internalIp, context);

                TestRequest request = TestRequest.builder()
                    .url(url)
                    .method(endpoint.getMethod())
                    .headers(context.getAuthHeaders())
                    .build();

                TestResponse response = executeTest(httpClient, request,
                    "Internal IP: " + internalIp);
                testsExecuted++;

                if (isSsrfSuccessful(response, internalIp)) {
                    VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                        .type(VulnerabilityReport.VulnerabilityType.SSRF)
                        .severity(Severity.HIGH)
                        .endpoint(endpoint)
                        .title("SSRF to Internal Network Resource")
                        .description(
                            "Server-Side Request Forgery vulnerability allows access to internal network resources. " +
                            "By injecting '" + internalIp + "' into the '" + param.getName() + "' parameter, " +
                            "the application can be used to scan and interact with internal services, " +
                            "potentially bypassing firewall restrictions and accessing sensitive internal systems."
                        )
                        .exploitRequest(request)
                        .exploitResponse(response)
                        .addEvidence("parameter", param.getName())
                        .addEvidence("injectedUrl", internalIp)
                        .addEvidence("statusCode", response.getStatusCode())
                        .addRecommendation("Validate and whitelist allowed destination hosts")
                        .addRecommendation("Block private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)")
                        .addRecommendation("Use DNS resolution validation")
                        .addRecommendation("Implement network-level restrictions")
                        .reproductionSteps(
                            "1. Send " + endpoint.getMethod() + " request\n" +
                            "2. Set '" + param.getName() + "' to: " + internalIp + "\n" +
                            "3. Application fetches internal resource\n" +
                            "4. Can be used to map internal network and access restricted services"
                        )
                        .build();

                    return new SsrfTestResult(Optional.of(vulnerability), testsExecuted);
                }
            }
        }

        return new SsrfTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Test protocol smuggling (file://, dict://, gopher://, etc.).
     */
    private SsrfTestResult testProtocolSmuggling(
        ApiEndpoint endpoint,
        List<ParameterSpec> urlParams,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing protocol smuggling for: " + endpoint);

        int testsExecuted = 0;

        for (ParameterSpec param : urlParams) {
            for (String dangerousProtocol : DANGEROUS_PROTOCOLS) {
                String url = buildUrlWithParameter(endpoint, param, dangerousProtocol, context);

                TestRequest request = TestRequest.builder()
                    .url(url)
                    .method(endpoint.getMethod())
                    .headers(context.getAuthHeaders())
                    .build();

                TestResponse response = executeTest(httpClient, request,
                    "Protocol: " + dangerousProtocol);
                testsExecuted++;

                if (isSsrfSuccessful(response, dangerousProtocol)) {
                    VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                        .type(VulnerabilityReport.VulnerabilityType.SSRF)
                        .severity(Severity.CRITICAL)
                        .endpoint(endpoint)
                        .title("SSRF with Protocol Smuggling")
                        .description(
                            "Server-Side Request Forgery vulnerability allows protocol smuggling. " +
                            "The application accepts dangerous URL schemes like '" + dangerousProtocol + "' " +
                            "which can be used to read local files, access internal services via alternative " +
                            "protocols, or perform other attacks beyond HTTP/HTTPS."
                        )
                        .exploitRequest(request)
                        .exploitResponse(response)
                        .addEvidence("parameter", param.getName())
                        .addEvidence("injectedProtocol", dangerousProtocol)
                        .addEvidence("statusCode", response.getStatusCode())
                        .addRecommendation("Strictly whitelist allowed protocols (http, https only)")
                        .addRecommendation("Reject URLs with file://, dict://, gopher://, ldap:// schemes")
                        .addRecommendation("Use URL parsing libraries with protocol validation")
                        .addRecommendation("Implement content-type validation for responses")
                        .reproductionSteps(
                            "1. Send " + endpoint.getMethod() + " request\n" +
                            "2. Set '" + param.getName() + "' to: " + dangerousProtocol + "\n" +
                            "3. Application processes dangerous protocol\n" +
                            "4. Can read local files or interact with non-HTTP services"
                        )
                        .build();

                    return new SsrfTestResult(Optional.of(vulnerability), testsExecuted);
                }
            }
        }

        return new SsrfTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Test localhost bypass techniques.
     */
    private SsrfTestResult testBypassTechniques(
        ApiEndpoint endpoint,
        List<ParameterSpec> urlParams,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing bypass techniques for: " + endpoint);

        int testsExecuted = 0;

        for (ParameterSpec param : urlParams) {
            for (String bypassUrl : BYPASS_TECHNIQUES) {
                String url = buildUrlWithParameter(endpoint, param, bypassUrl, context);

                TestRequest request = TestRequest.builder()
                    .url(url)
                    .method(endpoint.getMethod())
                    .headers(context.getAuthHeaders())
                    .build();

                TestResponse response = executeTest(httpClient, request,
                    "Bypass: " + bypassUrl);
                testsExecuted++;

                if (isSsrfSuccessful(response, bypassUrl)) {
                    VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                        .type(VulnerabilityReport.VulnerabilityType.SSRF)
                        .severity(Severity.HIGH)
                        .endpoint(endpoint)
                        .title("SSRF Filter Bypass via Alternative Encoding")
                        .description(
                            "Server-Side Request Forgery vulnerability with insufficient input validation. " +
                            "The application's SSRF protection can be bypassed using alternative IP encodings " +
                            "like '" + bypassUrl + "'. This indicates weak validation that only checks for " +
                            "simple patterns rather than properly resolving and validating destinations."
                        )
                        .exploitRequest(request)
                        .exploitResponse(response)
                        .addEvidence("parameter", param.getName())
                        .addEvidence("bypassTechnique", bypassUrl)
                        .addEvidence("statusCode", response.getStatusCode())
                        .addRecommendation("Use DNS resolution before validation")
                        .addRecommendation("Validate resolved IP addresses, not just URL strings")
                        .addRecommendation("Implement proper IP parsing and normalization")
                        .addRecommendation("Block all localhost representations (127.0.0.1, ::1, 0.0.0.0, etc.)")
                        .reproductionSteps(
                            "1. Send " + endpoint.getMethod() + " request\n" +
                            "2. Set '" + param.getName() + "' to: " + bypassUrl + "\n" +
                            "3. Bypass filters using alternative encoding\n" +
                            "4. Access internal resources despite filtering attempts"
                        )
                        .build();

                    return new SsrfTestResult(Optional.of(vulnerability), testsExecuted);
                }
            }
        }

        return new SsrfTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Build URL with parameter injection.
     */
    private String buildUrlWithParameter(
        ApiEndpoint endpoint,
        ParameterSpec param,
        String injectedValue,
        ScanContext context
    ) {
        String path = endpoint.getPath();

        // Handle different parameter locations
        switch (param.getIn().toLowerCase()) {
            case "query":
                String separator = path.contains("?") ? "&" : "?";
                return context.buildUrl(path + separator + param.getName() + "=" + injectedValue);
            case "path":
                // Replace path parameter
                return context.buildUrl(path.replace("{" + param.getName() + "}", injectedValue));
            default:
                // Default to query parameter
                String sep = path.contains("?") ? "&" : "?";
                return context.buildUrl(path + sep + param.getName() + "=" + injectedValue);
        }
    }

    /**
     * Check if SSRF was successful based on response characteristics.
     */
    private boolean isSsrfSuccessful(TestResponse response, String injectedUrl) {
        int status = response.getStatusCode();
        String body = response.getBody();

        // Success indicators:
        // 1. 2xx status code
        if (status >= 200 && status < 300) {
            // Check if response contains signs of successful SSRF
            if (body.length() > 100) { // Non-empty response
                return true;
            }

            // Check for URL reflection in response
            if (URL_REFLECTION_PATTERN.matcher(body).find()) {
                return true;
            }

            // Cloud metadata indicators
            if (injectedUrl.contains("169.254.169.254") || injectedUrl.contains("metadata")) {
                if (body.contains("ami-") || body.contains("instance") ||
                    body.contains("iam") || body.contains("security-credentials")) {
                    return true;
                }
            }

            // File read indicators
            if (injectedUrl.startsWith("file://")) {
                if (body.contains("root:") || body.contains("[extensions]")) {
                    return true;
                }
            }
        }

        // Also check for timing-based detection (slow response might indicate SSRF)
        // This is a simple heuristic
        return false;
    }

    /**
     * Result of an SSRF test case.
     */
    private record SsrfTestResult(
        Optional<VulnerabilityReport> vulnerability,
        int testsExecuted
    ) {}
}
