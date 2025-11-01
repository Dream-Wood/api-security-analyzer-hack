package active.scanner.ssrf;

import active.model.ApiEndpoint;
import active.model.VulnerabilityReport;
import active.scanner.ScanContext;
import active.scanner.ScannerConfig;
import model.ParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for SsrfScanner.
 */
class SsrfScannerTest {

    private SsrfScanner scanner;
    private ScanContext context;

    @BeforeEach
    void setUp() {
        scanner = new SsrfScanner(ScannerConfig.defaultConfig());
        context = ScanContext.builder()
            .baseUrl("http://localhost:5000")
            .addAuthHeader("Authorization", "Bearer valid_token_123")
            .verbose(true)
            .build();
    }

    @Test
    void testScannerMetadata() {
        assertEquals("ssrf-scanner", scanner.getId());
        assertEquals("Server-Side Request Forgery (SSRF) Scanner", scanner.getName());
        assertNotNull(scanner.getDescription());
        assertTrue(scanner.getDescription().length() > 0);

        List<VulnerabilityReport.VulnerabilityType> types = scanner.getDetectedVulnerabilities();
        assertEquals(1, types.size());
        assertTrue(types.contains(VulnerabilityReport.VulnerabilityType.SSRF));
    }

    @Test
    void testIsApplicableToUrlParameter() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/fetch")
            .method("GET")
            .parameters(List.of(
                ParameterSpec.builder()
                    .name("url")
                    .in("query")
                    .required(true)
                    .build()
            ))
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToWebhookParameter() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/webhook/register")
            .method("POST")
            .parameters(List.of(
                ParameterSpec.builder()
                    .name("webhookUrl")
                    .in("query")
                    .required(true)
                    .build()
            ))
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToCallbackParameter() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/oauth/callback")
            .method("GET")
            .parameters(List.of(
                ParameterSpec.builder()
                    .name("callbackUrl")
                    .in("query")
                    .required(false)
                    .build()
            ))
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToRedirectParameter() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/redirect")
            .method("GET")
            .parameters(List.of(
                ParameterSpec.builder()
                    .name("redirectUrl")
                    .in("query")
                    .required(true)
                    .build()
            ))
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToFetchEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/fetch/content")
            .method("POST")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToProxyEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/proxy")
            .method("GET")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToImportEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/import/data")
            .method("POST")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsNotApplicableToHealthEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/health")
            .method("GET")
            .build();

        assertFalse(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsNotApplicableToStatusEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/status")
            .method("GET")
            .build();

        assertFalse(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsNotApplicableToMetricsEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/metrics")
            .method("GET")
            .build();

        assertFalse(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsNotApplicableToEndpointWithoutUrlParams() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/users/{id}")
            .method("GET")
            .parameters(List.of(
                ParameterSpec.builder()
                    .name("id")
                    .in("path")
                    .required(true)
                    .build()
            ))
            .build();

        assertFalse(scanner.isApplicable(endpoint));
    }

    @Test
    void testConfig() {
        ScannerConfig customConfig = ScannerConfig.builder()
            .maxTestsPerEndpoint(5)
            .timeoutSeconds(3)
            .build();

        scanner.setConfig(customConfig);
        assertEquals(customConfig, scanner.getConfig());
    }
}
