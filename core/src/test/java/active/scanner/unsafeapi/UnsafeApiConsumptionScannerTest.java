package active.scanner.unsafeapi;

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
 * Unit tests for UnsafeApiConsumptionScanner.
 */
class UnsafeApiConsumptionScannerTest {

    private UnsafeApiConsumptionScanner scanner;
    private ScanContext context;

    @BeforeEach
    void setUp() {
        scanner = new UnsafeApiConsumptionScanner(ScannerConfig.defaultConfig());
        context = ScanContext.builder()
            .baseUrl("http://localhost:5000")
            .addAuthHeader("Authorization", "Bearer valid_token_123")
            .verbose(true)
            .build();
    }

    @Test
    void testScannerMetadata() {
        assertEquals("unsafe-api-consumption-scanner", scanner.getId());
        assertEquals("Unsafe API Consumption Scanner", scanner.getName());
        assertNotNull(scanner.getDescription());
        assertTrue(scanner.getDescription().length() > 0);

        List<VulnerabilityReport.VulnerabilityType> types = scanner.getDetectedVulnerabilities();
        assertEquals(1, types.size());
        assertTrue(types.contains(VulnerabilityReport.VulnerabilityType.UNSAFE_API_CONSUMPTION));
    }

    @Test
    void testIsApplicableToProxyEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/proxy/fetch")
            .method("GET")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToWebhookEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/webhook/callback")
            .method("POST")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToUrlParameterEndpoints() {
        ParameterSpec urlParam = ParameterSpec.builder()
            .name("url")
            .in("query")
            .type("string")
            .required(false)
            .build();

        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/data/fetch")
            .method("GET")
            .addParameter(urlParam)
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToCallbackParameterEndpoints() {
        ParameterSpec callbackParam = ParameterSpec.builder()
            .name("callback_url")
            .in("query")
            .type("string")
            .required(false)
            .build();

        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/integration/setup")
            .method("POST")
            .addParameter(callbackParam)
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToExternalEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/external/service")
            .method("GET")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToFetchEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/fetch/remote")
            .method("GET")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToIntegrationEndpoints() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/integrate/thirdparty")
            .method("POST")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToAllEndpoints() {
        // Scanner checks all endpoints by default (fallback to true)
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/users")
            .method("GET")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testConfigurationSettings() {
        ScannerConfig customConfig = ScannerConfig.builder()
            .maxTestsPerEndpoint(25)
            .timeoutSeconds(90)
            .build();

        UnsafeApiConsumptionScanner customScanner = new UnsafeApiConsumptionScanner(customConfig);
        assertEquals(customConfig, customScanner.getConfig());
    }

    @Test
    void testDefaultConfiguration() {
        UnsafeApiConsumptionScanner defaultScanner = new UnsafeApiConsumptionScanner();
        assertNotNull(defaultScanner.getConfig());
        assertEquals(ScannerConfig.defaultConfig().getMaxTestsPerEndpoint(),
                    defaultScanner.getConfig().getMaxTestsPerEndpoint());
    }

    @Test
    void testIsApplicableWithMultipleUrlParameters() {
        ParameterSpec urlParam1 = ParameterSpec.builder()
            .name("api_url")
            .in("query")
            .type("string")
            .required(false)
            .build();

        ParameterSpec urlParam2 = ParameterSpec.builder()
            .name("endpoint")
            .in("query")
            .type("string")
            .required(false)
            .build();

        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/data")
            .method("GET")
            .addParameter(urlParam1)
            .addParameter(urlParam2)
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }
}
