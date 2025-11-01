package active.scanner.brokenauth;

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
 * Unit tests for BrokenAuthenticationScanner.
 */
class BrokenAuthenticationScannerTest {

    private BrokenAuthenticationScanner scanner;
    private ScanContext context;

    @BeforeEach
    void setUp() {
        scanner = new BrokenAuthenticationScanner(ScannerConfig.defaultConfig());
        context = ScanContext.builder()
            .baseUrl("http://localhost:5000")
            .addAuthHeader("Authorization", "Bearer valid_token_123")
            .verbose(true)
            .build();
    }

    @Test
    void testScannerMetadata() {
        assertEquals("broken-authentication-scanner", scanner.getId());
        assertEquals("Broken Authentication Scanner", scanner.getName());
        assertNotNull(scanner.getDescription());
        assertTrue(scanner.getDescription().length() > 0);

        List<VulnerabilityReport.VulnerabilityType> types = scanner.getDetectedVulnerabilities();
        assertEquals(2, types.size());
        assertTrue(types.contains(VulnerabilityReport.VulnerabilityType.BROKEN_AUTHENTICATION));
        assertTrue(types.contains(VulnerabilityReport.VulnerabilityType.MISSING_RATE_LIMITING));
    }

    @Test
    void testIsApplicableToUserEndpoint() {
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
    void testIsNotApplicableToPublicEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/public/docs")
            .method("GET")
            .build();

        assertFalse(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToPostEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/users")
            .method("POST")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToDeleteEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/orders/{id}")
            .method("DELETE")
            .parameters(List.of(
                ParameterSpec.builder()
                    .name("id")
                    .in("path")
                    .required(true)
                    .build()
            ))
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToPutEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/products/{id}")
            .method("PUT")
            .parameters(List.of(
                ParameterSpec.builder()
                    .name("id")
                    .in("path")
                    .required(true)
                    .build()
            ))
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToPatchEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/settings")
            .method("PATCH")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsNotApplicableToRootPath() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/")
            .method("GET")
            .build();

        assertFalse(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsNotApplicableToApiRootPath() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api")
            .method("GET")
            .build();

        assertFalse(scanner.isApplicable(endpoint));
    }

    @Test
    void testScannerConfig() {
        ScannerConfig config = scanner.getConfig();
        assertNotNull(config);
        assertTrue(config.isEnabled());
        assertTrue(config.getMaxTestsPerEndpoint() > 0);
    }

    @Test
    void testScannerConfigUpdate() {
        ScannerConfig newConfig = ScannerConfig.builder()
            .enabled(false)
            .maxTestsPerEndpoint(20)
            .build();

        scanner.setConfig(newConfig);

        assertEquals(newConfig, scanner.getConfig());
        assertFalse(scanner.getConfig().isEnabled());
        assertEquals(20, scanner.getConfig().getMaxTestsPerEndpoint());
    }

    @Test
    void testScanContextWithAuthHeaders() {
        assertNotNull(context.getAuthHeaders());
        assertFalse(context.getAuthHeaders().isEmpty());
        assertEquals("Bearer valid_token_123", context.getAuthHeaders().get("Authorization"));
    }

    @Test
    void testScanContextWithoutAuthHeaders() {
        ScanContext noAuthContext = ScanContext.builder()
            .baseUrl("http://localhost:5000")
            .build();

        assertNotNull(noAuthContext.getAuthHeaders());
        assertTrue(noAuthContext.getAuthHeaders().isEmpty());
    }
}
