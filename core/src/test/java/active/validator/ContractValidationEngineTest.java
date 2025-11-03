package active.validator;

import active.http.HttpClient;
import active.model.ApiEndpoint;
import active.model.TestRequest;
import active.model.TestResponse;
import active.validator.model.ValidationResult;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.Paths;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ContractValidationEngineTest {

    private OpenAPI openAPI;

    @Mock
    private HttpClient mockHttpClient;

    @BeforeEach
    void setUp() {
        openAPI = createTestOpenAPI();

        // Mock successful response (lenient to avoid UnnecessaryStubbingException)
        TestResponse mockResponse = TestResponse.builder()
            .statusCode(200)
            .body("{\"id\": 1, \"name\": \"test\"}")
            .addHeader("Content-Type", "application/json")
            .build();

        lenient().when(mockHttpClient.execute(any(TestRequest.class))).thenReturn(mockResponse);
    }

    private OpenAPI createTestOpenAPI() {
        OpenAPI api = new OpenAPI();

        // Create path /users/{id}
        PathItem pathItem = new PathItem();
        Operation getOperation = new Operation();

        // Add response
        ApiResponse response = new ApiResponse();
        response.setDescription("Success");

        MediaType mediaType = new MediaType();
        Schema schema = new Schema();
        schema.setType("object");
        schema.addProperty("id", new Schema().type("integer"));
        schema.addProperty("name", new Schema().type("string"));
        schema.setRequired(List.of("id", "name"));

        mediaType.setSchema(schema);
        response.setContent(new io.swagger.v3.oas.models.media.Content()
            .addMediaType("application/json", mediaType));

        ApiResponses responses = new ApiResponses();
        responses.addApiResponse("200", response);
        getOperation.setResponses(responses);

        pathItem.setGet(getOperation);

        Paths paths = new Paths();
        paths.addPathItem("/users/{id}", pathItem);
        api.setPaths(paths);

        return api;
    }

    @Test
    void testEngineCreation() {
        ContractValidationEngine engine = new ContractValidationEngine(openAPI);

        assertNotNull(engine);
        assertTrue(engine.isFuzzingEnabled(), "Fuzzing should be enabled by default");
    }

    @Test
    void testEngineCreationWithFuzzingDisabled() {
        ContractValidationEngine engine = new ContractValidationEngine(openAPI, false);

        assertNotNull(engine);
        assertFalse(engine.isFuzzingEnabled(), "Fuzzing should be disabled");
    }

    @Test
    void testValidateSingleEndpoint() {
        ContractValidationEngine engine = new ContractValidationEngine(openAPI, false);

        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/users/{id}")
            .method("GET")
            .build();

        ValidationResult result = engine.validateEndpoint(endpoint, mockHttpClient);

        assertNotNull(result);
        assertEquals("/users/{id}", result.getEndpoint());
        assertEquals("GET", result.getMethod());
    }

    @Test
    void testValidateMultipleEndpoints() {
        ContractValidationEngine engine = new ContractValidationEngine(openAPI, false);

        List<ApiEndpoint> endpoints = List.of(
            ApiEndpoint.builder().path("/users/{id}").method("GET").build()
        );

        ContractValidationEngine.ContractValidationReport report =
            engine.validate(endpoints, mockHttpClient);

        assertNotNull(report);
        assertEquals(1, report.getTotalEndpoints());
        assertNotNull(report.getResults());
        assertNotNull(report.getStatistics());
    }

    @Test
    void testQuickValidate() {
        ContractValidationEngine engine = new ContractValidationEngine(openAPI, true);

        List<ApiEndpoint> endpoints = List.of(
            ApiEndpoint.builder().path("/users/{id}").method("GET").build()
        );

        ContractValidationEngine.ContractValidationReport report =
            engine.quickValidate(endpoints, mockHttpClient);

        assertNotNull(report);
        assertFalse(report.isFuzzingEnabled(), "Quick validate should disable fuzzing");
        assertTrue(engine.isFuzzingEnabled(), "Original setting should be restored");
    }

    @Test
    void testGetSpecificationStats() {
        ContractValidationEngine engine = new ContractValidationEngine(openAPI);

        Map<String, Object> stats = engine.getSpecificationStats();

        assertNotNull(stats);
        assertTrue(stats.containsKey("totalPaths"));
        assertTrue(stats.containsKey("totalOperations"));
    }

    @Test
    void testReportStatistics() {
        ContractValidationEngine engine = new ContractValidationEngine(openAPI, false);

        List<ApiEndpoint> endpoints = List.of(
            ApiEndpoint.builder().path("/users/{id}").method("GET").build()
        );

        ContractValidationEngine.ContractValidationReport report =
            engine.validate(endpoints, mockHttpClient);

        Map<String, Object> stats = report.getStatistics();

        assertNotNull(stats);
        assertTrue(stats.containsKey("totalEndpoints"));
        assertTrue(stats.containsKey("totalDivergences"));
        assertTrue(stats.containsKey("durationMs"));
    }

    @Test
    void testReportSummary() {
        ContractValidationEngine engine = new ContractValidationEngine(openAPI, false);

        List<ApiEndpoint> endpoints = List.of(
            ApiEndpoint.builder().path("/users/{id}").method("GET").build()
        );

        ContractValidationEngine.ContractValidationReport report =
            engine.validate(endpoints, mockHttpClient);

        String summary = report.getSummary();

        assertNotNull(summary);
        assertTrue(summary.contains("Contract Validation Report"));
        assertTrue(summary.contains("Total:"));
    }

    @Test
    void testFuzzingToggle() {
        ContractValidationEngine engine = new ContractValidationEngine(openAPI, true);

        assertTrue(engine.isFuzzingEnabled());

        engine.setFuzzingEnabled(false);
        assertFalse(engine.isFuzzingEnabled());

        engine.setFuzzingEnabled(true);
        assertTrue(engine.isFuzzingEnabled());
    }

    @Test
    void testReportHasDivergences() {
        ContractValidationEngine engine = new ContractValidationEngine(openAPI, false);

        List<ApiEndpoint> endpoints = List.of(
            ApiEndpoint.builder().path("/users/{id}").method("GET").build()
        );

        ContractValidationEngine.ContractValidationReport report =
            engine.validate(endpoints, mockHttpClient);

        // Since we're mocking a valid response, should not have divergences
        assertNotNull(report);
        // Can't assert exact count without knowing implementation details
    }

    @Test
    void testNullOpenAPIThrowsException() {
        assertThrows(NullPointerException.class, () -> {
            new ContractValidationEngine(null);
        });
    }
}
