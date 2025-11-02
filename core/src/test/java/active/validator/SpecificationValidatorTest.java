package active.validator;

import active.model.TestResponse;
import active.validator.model.Divergence;
import active.validator.model.DivergenceType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SpecificationValidatorTest {

    private SpecificationValidator validator;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        validator = new SpecificationValidator();
        objectMapper = new ObjectMapper();
    }

    @Test
    void testValidateResponse_CorrectStatusCode() throws Exception {
        // Arrange
        String responseBody = "{\"id\": 1, \"name\": \"test\"}";
        TestResponse response = TestResponse.builder()
            .statusCode(200)
            .body(responseBody)
            .addHeader("Content-Type", "application/json")
            .build();

        String schemaJson = """
            {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"}
                },
                "required": ["id", "name"]
            }
            """;
        JsonNode schema = objectMapper.readTree(schemaJson);

        // Act
        List<Divergence> divergences = validator.validateResponse(response, schema, 200);

        // Assert
        assertTrue(divergences.isEmpty(), "Should have no divergences for valid response");
    }

    @Test
    void testValidateResponse_WrongStatusCode() throws Exception {
        // Arrange
        String responseBody = "{\"error\": \"Not found\"}";
        TestResponse response = TestResponse.builder()
            .statusCode(404)
            .body(responseBody)
            .build();

        String schemaJson = "{\"type\": \"object\"}";
        JsonNode schema = objectMapper.readTree(schemaJson);

        // Act
        List<Divergence> divergences = validator.validateResponse(response, schema, 200);

        // Assert
        assertEquals(1, divergences.size());
        assertEquals(DivergenceType.UNEXPECTED_STATUS_CODE, divergences.get(0).getType());
        assertEquals(404, divergences.get(0).getActualValue());
    }

    @Test
    void testValidateResponse_MissingRequiredField() throws Exception {
        // Arrange
        String responseBody = "{\"id\": 1}"; // Missing 'name'
        TestResponse response = TestResponse.builder()
            .statusCode(200)
            .body(responseBody)
            .addHeader("Content-Type", "application/json")
            .build();

        String schemaJson = """
            {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"}
                },
                "required": ["id", "name"]
            }
            """;
        JsonNode schema = objectMapper.readTree(schemaJson);

        // Act
        List<Divergence> divergences = validator.validateResponse(response, schema, 200);

        // Assert
        assertFalse(divergences.isEmpty());
        assertTrue(divergences.stream()
            .anyMatch(d -> d.getType() == DivergenceType.MISSING_REQUIRED_FIELD));
    }

    @Test
    void testValidateResponse_TypeMismatch() throws Exception {
        // Arrange
        String responseBody = "{\"id\": \"not-a-number\", \"name\": \"test\"}";
        TestResponse response = TestResponse.builder()
            .statusCode(200)
            .body(responseBody)
            .addHeader("Content-Type", "application/json")
            .build();

        String schemaJson = """
            {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"}
                },
                "required": ["id", "name"]
            }
            """;
        JsonNode schema = objectMapper.readTree(schemaJson);

        // Act
        List<Divergence> divergences = validator.validateResponse(response, schema, 200);

        // Assert
        assertTrue(divergences.stream()
            .anyMatch(d -> d.getType() == DivergenceType.TYPE_MISMATCH));
    }

    @Test
    void testValidateResponse_UnexpectedField() throws Exception {
        // Arrange
        String responseBody = "{\"id\": 1, \"name\": \"test\", \"extra\": \"field\"}";
        TestResponse response = TestResponse.builder()
            .statusCode(200)
            .body(responseBody)
            .addHeader("Content-Type", "application/json")
            .build();

        String schemaJson = """
            {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"}
                },
                "required": ["id", "name"],
                "additionalProperties": false
            }
            """;
        JsonNode schema = objectMapper.readTree(schemaJson);

        // Act
        List<Divergence> divergences = validator.validateResponse(response, schema, 200);

        // Assert
        assertTrue(divergences.stream()
            .anyMatch(d -> d.getType() == DivergenceType.ADDITIONAL_PROPERTIES_FORBIDDEN));
    }

    @Test
    void testValidateResponse_NullRequiredField() throws Exception {
        // Arrange
        String responseBody = "{\"id\": null, \"name\": \"test\"}";
        TestResponse response = TestResponse.builder()
            .statusCode(200)
            .body(responseBody)
            .addHeader("Content-Type", "application/json")
            .build();

        String schemaJson = """
            {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"}
                },
                "required": ["id", "name"]
            }
            """;
        JsonNode schema = objectMapper.readTree(schemaJson);

        // Act
        List<Divergence> divergences = validator.validateResponse(response, schema, 200);

        // Assert
        assertTrue(divergences.stream()
            .anyMatch(d -> d.getType() == DivergenceType.NULL_REQUIRED_FIELD));
    }

    @Test
    void testValidateResponse_InvalidJSON() {
        // Arrange
        String responseBody = "{invalid json}";
        TestResponse response = TestResponse.builder()
            .statusCode(200)
            .body(responseBody)
            .addHeader("Content-Type", "application/json")
            .build();

        JsonNode schema = objectMapper.createObjectNode();

        // Act
        List<Divergence> divergences = validator.validateResponse(response, schema, 200);

        // Assert
        assertFalse(divergences.isEmpty());
        assertTrue(divergences.stream()
            .anyMatch(d -> d.getType() == DivergenceType.SCHEMA_VIOLATION));
    }

    @Test
    void testValidateResponse_ArrayValidation() throws Exception {
        // Arrange
        String responseBody = "[{\"id\": 1}, {\"id\": 2}]";
        TestResponse response = TestResponse.builder()
            .statusCode(200)
            .body(responseBody)
            .addHeader("Content-Type", "application/json")
            .build();

        String schemaJson = """
            {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"}
                    },
                    "required": ["id"]
                }
            }
            """;
        JsonNode schema = objectMapper.readTree(schemaJson);

        // Act
        List<Divergence> divergences = validator.validateResponse(response, schema, 200);

        // Assert
        assertTrue(divergences.isEmpty(), "Valid array should have no divergences");
    }

    @Test
    void testValidateResponse_EnumViolation() throws Exception {
        // Arrange
        String responseBody = "{\"status\": \"INVALID\"}";
        TestResponse response = TestResponse.builder()
            .statusCode(200)
            .body(responseBody)
            .addHeader("Content-Type", "application/json")
            .build();

        String schemaJson = """
            {
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": ["ACTIVE", "INACTIVE", "PENDING"]
                    }
                },
                "required": ["status"]
            }
            """;
        JsonNode schema = objectMapper.readTree(schemaJson);

        // Act
        List<Divergence> divergences = validator.validateResponse(response, schema, 200);

        // Assert
        assertTrue(divergences.stream()
            .anyMatch(d -> d.getType() == DivergenceType.INVALID_ENUM_VALUE));
    }
}
