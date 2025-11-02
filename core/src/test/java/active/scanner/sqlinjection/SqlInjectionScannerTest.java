package active.scanner.sqlinjection;

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
 * Unit tests for SqlInjectionScanner.
 */
class SqlInjectionScannerTest {

    private SqlInjectionScanner scanner;
    private ScanContext context;

    @BeforeEach
    void setUp() {
        scanner = new SqlInjectionScanner(ScannerConfig.defaultConfig());
        context = ScanContext.builder()
            .baseUrl("http://localhost:5000")
            .verbose(true)
            .build();
    }

    @Test
    void testScannerMetadata() {
        assertEquals("sql-injection-scanner", scanner.getId());
        assertEquals("SQL Injection Scanner", scanner.getName());
        assertNotNull(scanner.getDescription());
        assertTrue(scanner.getDescription().length() > 0);

        List<VulnerabilityReport.VulnerabilityType> types = scanner.getDetectedVulnerabilities();
        assertEquals(1, types.size());
        assertEquals(VulnerabilityReport.VulnerabilityType.SQL_INJECTION, types.get(0));
    }

    @Test
    void testIsApplicableToGetWithQueryParameters() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/users")
            .method("GET")
            .parameters(List.of(
                ParameterSpec.builder()
                    .name("id")
                    .in("query")
                    .required(false)
                    .build()
            ))
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToGetWithPathParameters() {
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
    void testIsApplicableToPostEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/users")
            .method("POST")
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
    void testIsApplicableToPatchEndpoint() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/users/{id}")
            .method("PATCH")
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsNotApplicableToGetWithoutParameters() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/users")
            .method("GET")
            .build();

        assertFalse(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsNotApplicableToDeleteWithoutParameters() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/users")
            .method("DELETE")
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
            .maxTestsPerEndpoint(5)
            .build();

        scanner.setConfig(newConfig);

        assertEquals(newConfig, scanner.getConfig());
        assertFalse(scanner.getConfig().isEnabled());
        assertEquals(5, scanner.getConfig().getMaxTestsPerEndpoint());
    }

    @Test
    void testIsApplicableWithMultipleQueryParameters() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/search")
            .method("GET")
            .parameters(List.of(
                ParameterSpec.builder()
                    .name("query")
                    .in("query")
                    .required(false)
                    .build(),
                ParameterSpec.builder()
                    .name("limit")
                    .in("query")
                    .required(false)
                    .build()
            ))
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }

    @Test
    void testIsApplicableToEndpointWithMixedParameters() {
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/api/users/{userId}/posts")
            .method("GET")
            .parameters(List.of(
                ParameterSpec.builder()
                    .name("userId")
                    .in("path")
                    .required(true)
                    .build(),
                ParameterSpec.builder()
                    .name("status")
                    .in("query")
                    .required(false)
                    .build()
            ))
            .build();

        assertTrue(scanner.isApplicable(endpoint));
    }
}
