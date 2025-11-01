package active.scanner.businessflow;

import active.model.ApiEndpoint;
import active.model.VulnerabilityReport;
import active.scanner.ScanContext;
import active.scanner.ScannerConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for UnrestrictedBusinessFlowScanner.
 */
class UnrestrictedBusinessFlowScannerTest {

    private UnrestrictedBusinessFlowScanner scanner;
    private ScanContext context;

    @BeforeEach
    void setUp() {
        scanner = new UnrestrictedBusinessFlowScanner(ScannerConfig.defaultConfig());
        context = ScanContext.builder()
            .baseUrl("http://localhost:5000")
            .addAuthHeader("Authorization", "Bearer valid_token_123")
            .verbose(true)
            .build();
    }

    @Test
    void testScannerMetadata() {
        assertEquals("unrestricted-business-flow-scanner", scanner.getId());
        assertEquals("Unrestricted Business Flow Scanner", scanner.getName());
        assertNotNull(scanner.getDescription());
        assertTrue(scanner.getDescription().length() > 0);

        List<VulnerabilityReport.VulnerabilityType> types = scanner.getDetectedVulnerabilities();
        assertEquals(1, types.size());
        assertTrue(types.contains(VulnerabilityReport.VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW));
    }

    @Test
    void testIsApplicableToPurchaseEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/purchase")
            .method("POST")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToPaymentEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/payment/process")
            .method("POST")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToPostEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/orders")
            .method("POST")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToDeleteEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/users/{id}")
            .method("DELETE")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToPutEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/users/{id}")
            .method("PUT")
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
    void testIsNotApplicableToPingEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/ping")
            .method("GET")
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
