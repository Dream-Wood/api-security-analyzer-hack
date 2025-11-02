package active.validator;

import active.model.ApiEndpoint;
import active.validator.model.FuzzTestCase;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import model.ParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class FuzzingGeneratorTest {

    private FuzzingGenerator generator;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        generator = new FuzzingGenerator();
        objectMapper = new ObjectMapper();
    }

    @Test
    void testGenerateFuzzTests_WithParameters() {
        // Arrange
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/users/{id}")
            .method("GET")
            .addParameter(ParameterSpec.builder()
                .name("id")
                .in("path")
                .type("integer")
                .required(true)
                .build())
            .addParameter(ParameterSpec.builder()
                .name("filter")
                .in("query")
                .type("string")
                .required(false)
                .build())
            .build();

        // Act
        List<FuzzTestCase> testCases = generator.generateFuzzTests(endpoint, Optional.empty());

        // Assert
        assertFalse(testCases.isEmpty(), "Should generate fuzz tests for parameters");

        // Check for different categories
        assertTrue(testCases.stream().anyMatch(tc ->
            tc.getCategory() == FuzzTestCase.FuzzCategory.NULL_VALUES));
        assertTrue(testCases.stream().anyMatch(tc ->
            tc.getCategory() == FuzzTestCase.FuzzCategory.BOUNDARY_VALUE));
        assertTrue(testCases.stream().anyMatch(tc ->
            tc.getCategory() == FuzzTestCase.FuzzCategory.INJECTION));
    }

    @Test
    void testGenerateFuzzTests_WithBody() throws Exception {
        // Arrange
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/users")
            .method("POST")
            .build();

        String schemaJson = """
            {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "age": {"type": "integer"}
                },
                "required": ["name"],
                "additionalProperties": false
            }
            """;
        JsonNode schema = objectMapper.readTree(schemaJson);

        // Act
        List<FuzzTestCase> testCases = generator.generateFuzzTests(endpoint, Optional.of(schema));

        // Assert
        assertFalse(testCases.isEmpty(), "Should generate fuzz tests for body");

        // Check for body-related tests
        assertTrue(testCases.stream().anyMatch(tc ->
            tc.getBodyPayload() != null));
        assertTrue(testCases.stream().anyMatch(tc ->
            tc.getCategory() == FuzzTestCase.FuzzCategory.TYPE_CONFUSION));
    }

    @Test
    void testGenerateFuzzTests_InjectionPayloads() {
        // Arrange
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/search")
            .method("GET")
            .addParameter(ParameterSpec.builder()
                .name("query")
                .in("query")
                .type("string")
                .build())
            .build();

        // Act
        List<FuzzTestCase> testCases = generator.generateFuzzTests(endpoint, Optional.empty());

        // Assert
        List<FuzzTestCase> injectionTests = testCases.stream()
            .filter(tc -> tc.getCategory() == FuzzTestCase.FuzzCategory.INJECTION)
            .toList();

        assertFalse(injectionTests.isEmpty(), "Should generate injection tests");
    }

    @Test
    void testGenerateFuzzTests_BoundaryValues() {
        // Arrange
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/items")
            .method("POST")
            .build();

        String schemaJson = "{\"type\": \"object\"}";

        // Act
        List<FuzzTestCase> testCases = generator.generateFuzzTests(endpoint, Optional.empty());

        // Assert
        List<FuzzTestCase> boundaryTests = testCases.stream()
            .filter(tc -> tc.getCategory() == FuzzTestCase.FuzzCategory.BOUNDARY_VALUE)
            .toList();

        assertFalse(boundaryTests.isEmpty(), "Should generate boundary value tests");
    }

    @Test
    void testGenerateFuzzTests_SpecialCharacters() {
        // Arrange
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/test")
            .method("GET")
            .addParameter(ParameterSpec.builder()
                .name("input")
                .in("query")
                .type("string")
                .build())
            .build();

        // Act
        List<FuzzTestCase> testCases = generator.generateFuzzTests(endpoint, Optional.empty());

        // Assert
        assertTrue(testCases.stream().anyMatch(tc ->
            tc.getCategory() == FuzzTestCase.FuzzCategory.SPECIAL_CHARACTERS));
    }

    @Test
    void testGenerateFuzzTests_EmptyAndNull() {
        // Arrange
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/test")
            .method("GET")
            .addParameter(ParameterSpec.builder()
                .name("param")
                .in("query")
                .type("string")
                .build())
            .build();

        // Act
        List<FuzzTestCase> testCases = generator.generateFuzzTests(endpoint, Optional.empty());

        // Assert
        assertTrue(testCases.stream().anyMatch(tc ->
            tc.getName().contains("Null parameter")));
        assertTrue(testCases.stream().anyMatch(tc ->
            tc.getName().contains("Empty parameter")));
    }

    @Test
    void testGenerateFuzzTests_NoParametersNoSchema() {
        // Arrange
        ApiEndpoint endpoint = ApiEndpoint.builder()
            .path("/health")
            .method("GET")
            .build();

        // Act
        List<FuzzTestCase> testCases = generator.generateFuzzTests(endpoint, Optional.empty());

        // Assert
        // Should still generate some generic tests
        assertNotNull(testCases);
    }
}
