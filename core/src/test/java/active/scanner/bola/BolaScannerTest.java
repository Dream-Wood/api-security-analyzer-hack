package active.scanner.bola;

import active.http.HttpClient;
import active.http.HttpClientConfig;
import active.http.StandardHttpClient;
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
 * Unit tests for BolaScanner without mocking frameworks.
 */
class BolaScannerTest {

    private BolaScanner scanner;
    private ScanContext context;

    @BeforeEach
    void setUp() {
        scanner = new BolaScanner(ScannerConfig.defaultConfig());
        context = ScanContext.builder()
            .baseUrl("http://localhost:5000")
            .verbose(true)
            .build();
    }

    @Test
    void testScannerMetadata() {
        assertEquals("bola-scanner", scanner.getId());
        assertEquals("BOLA/IDOR Scanner", scanner.getName());
        assertNotNull(scanner.getDescription());
        assertTrue(scanner.getDescription().length() > 0);

        List<VulnerabilityReport.VulnerabilityType> types = scanner.getDetectedVulnerabilities();
        assertEquals(1, types.size());
        assertEquals(VulnerabilityReport.VulnerabilityType.BOLA, types.get(0));
    }

    @Test
    void testIsApplicableToGetWithIdParameter() {
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
    void testIsNotApplicableToPostWithoutIdParameter() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/users")
            .method("POST")
            .build();

        assertFalse(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToDeleteWithId() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/users/{userId}")
            .method("DELETE")
            .parameters(List.of(
                ParameterSpec.builder()
                    .name("userId")
                    .in("path")
                    .required(true)
                    .build()
            ))
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToPutWithId() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/orders/{id}")
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
    void testIsNotApplicableToGetWithoutId() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/users")
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
            .maxTestsPerEndpoint(10)
            .build();

        scanner.setConfig(newConfig);

        assertEquals(newConfig, scanner.getConfig());
        assertFalse(scanner.getConfig().isEnabled());
        assertEquals(10, scanner.getConfig().getMaxTestsPerEndpoint());
    }
}
