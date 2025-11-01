package active.scanner.inventory;

import active.model.ApiEndpoint;
import active.model.VulnerabilityReport;
import active.scanner.ScanContext;
import active.scanner.ScannerConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ImproperInventoryScanner.
 */
class ImproperInventoryScannerTest {

    private ImproperInventoryScanner scanner;
    private ScanContext context;

    @BeforeEach
    void setUp() {
        scanner = new ImproperInventoryScanner(ScannerConfig.defaultConfig());
        context = ScanContext.builder()
            .baseUrl("http://localhost:5000")
            .addAuthHeader("Authorization", "Bearer valid_token_123")
            .verbose(true)
            .build();
    }

    @Test
    void testScannerMetadata() {
        assertEquals("improper-inventory-scanner", scanner.getId());
        assertEquals("Improper Inventory Management Scanner", scanner.getName());
        assertNotNull(scanner.getDescription());
        assertTrue(scanner.getDescription().length() > 0);

        List<VulnerabilityReport.VulnerabilityType> types = scanner.getDetectedVulnerabilities();
        assertEquals(1, types.size());
        assertTrue(types.contains(VulnerabilityReport.VulnerabilityType.IMPROPER_INVENTORY));
    }

    @Test
    void testIsApplicableToAllEndpoints() {
        // Inventory scanner should check all endpoints
        ApiEndpoint endpoint1 = ApiEndpoint.builder()
            .path("/api/users")
            .method("GET")
            .build();

        assertTrue(scanner.isApplicable(endpoint1));

        ApiEndpoint endpoint2 = ApiEndpoint.builder()
            .path("/api/v1/products")
            .method("GET")
            .build();

        assertTrue(scanner.isApplicable(endpoint2));

        ApiEndpoint endpoint3 = ApiEndpoint.builder()
            .path("/api/v2/admin/settings")
            .method("POST")
            .build();

        assertTrue(scanner.isApplicable(endpoint3));
    }

    @Test
    void testIsApplicableToVersionedEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/v1/users")
            .method("GET")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToOldVersionEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/v1/legacy/endpoint")
            .method("GET")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToUnversionedEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/data")
            .method("GET")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testConfigurationSettings() {
        ScannerConfig customConfig = ScannerConfig.builder()
            .maxTestsPerEndpoint(20)
            .timeoutSeconds(60)
            .build();

        ImproperInventoryScanner customScanner = new ImproperInventoryScanner(customConfig);
        assertEquals(customConfig, customScanner.getConfig());
    }

    @Test
    void testDefaultConfiguration() {
        ImproperInventoryScanner defaultScanner = new ImproperInventoryScanner();
        assertNotNull(defaultScanner.getConfig());
        assertEquals(ScannerConfig.defaultConfig().getMaxTestsPerEndpoint(),
                    defaultScanner.getConfig().getMaxTestsPerEndpoint());
    }
}
