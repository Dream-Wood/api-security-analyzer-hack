package active.scanner.misconfiguration;

import active.model.ApiEndpoint;
import active.model.VulnerabilityReport;
import active.scanner.ScanContext;
import active.scanner.ScannerConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for SecurityMisconfigurationScanner.
 */
class SecurityMisconfigurationScannerTest {

    private SecurityMisconfigurationScanner scanner;
    private ScanContext context;

    @BeforeEach
    void setUp() {
        scanner = new SecurityMisconfigurationScanner(ScannerConfig.defaultConfig());
        context = ScanContext.builder()
            .baseUrl("http://localhost:5000")
            .addAuthHeader("Authorization", "Bearer valid_token_123")
            .verbose(true)
            .build();
    }

    @Test
    void testScannerMetadata() {
        assertEquals("security-misconfiguration-scanner", scanner.getId());
        assertEquals("Security Misconfiguration Scanner", scanner.getName());
        assertNotNull(scanner.getDescription());
        assertTrue(scanner.getDescription().length() > 0);

        List<VulnerabilityReport.VulnerabilityType> types = scanner.getDetectedVulnerabilities();
        assertEquals(1, types.size());
        assertTrue(types.contains(VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION));
    }

    @Test
    void testIsApplicableToAllEndpoints() {
        // Security misconfiguration scanner should check all endpoints
        ApiEndpoint endpoint1 = ApiEndpoint.builder()
            .path("/api/users")
            .method("GET")
            .build();

        assertTrue(scanner.isApplicable(endpoint1));

        ApiEndpoint endpoint2 = ApiEndpoint.builder()
            .path("/api/admin/dashboard")
            .method("POST")
            .build();

        assertTrue(scanner.isApplicable(endpoint2));

        ApiEndpoint endpoint3 = ApiEndpoint.builder()
            .path("/health")
            .method("GET")
            .build();

        assertTrue(scanner.isApplicable(endpoint3));
    }

    @Test
    void testIsApplicableToAuthEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/auth/login")
            .method("POST")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToPaymentEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/payment/process")
            .method("POST")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToUserEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/users/{id}")
            .method("GET")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToAdminEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/admin/config")
            .method("GET")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToTransferEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/users/transfer")
            .method("POST")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToProfileEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/profile")
            .method("PUT")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToPasswordEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/auth/reset-password")
            .method("POST")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToAccountEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/account/settings")
            .method("PUT")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToTransactionEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/transactions/{id}")
            .method("GET")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
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
