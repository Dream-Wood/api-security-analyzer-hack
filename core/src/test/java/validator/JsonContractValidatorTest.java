package validator;

import model.Severity;
import model.ValidationFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JsonContractValidatorTest {

    @Test
    void validate_withTypeViolation_shouldReturnHighSeverity() throws Exception {
        String schema = """
                {
                  "type": "object",
                  "properties": {
                    "id": { "type": "integer" },
                    "name": { "type": "string" }
                  },
                  "required": ["id", "name"]
                }
                """;

        String instance = """
                {
                  "id": "not-an-integer",
                  "name": "Test"
                }
                """;

        JsonContractValidator validator = new JsonContractValidator();
        List<ValidationFinding> findings = validator.validate(schema, instance);

        assertFalse(findings.isEmpty(), "Should have violations");

        // Should have type violation
        boolean hasTypeViolation = findings.stream()
            .anyMatch(f -> f.getDetails() != null &&
                f.getDetails().toLowerCase().contains("type"));

        assertTrue(hasTypeViolation, "Should detect type violation");

        // Type violations should be HIGH severity
        boolean hasHighSeverity = findings.stream()
            .anyMatch(f -> f.getSeverity() == Severity.HIGH);

        assertTrue(hasHighSeverity, "Type violations should be HIGH severity");
    }

    @Test
    void validate_withMissingRequiredField_shouldReturnHighSeverity() throws Exception {
        String schema = """
                {
                  "type": "object",
                  "properties": {
                    "id": { "type": "integer" },
                    "name": { "type": "string" }
                  },
                  "required": ["id", "name"]
                }
                """;

        String instance = """
                {
                  "id": 123
                }
                """;

        JsonContractValidator validator = new JsonContractValidator();
        List<ValidationFinding> findings = validator.validate(schema, instance);

        assertFalse(findings.isEmpty(), "Should have violations");

        // Should have required field violation
        boolean hasRequiredViolation = findings.stream()
            .anyMatch(f -> f.getDetails() != null &&
                f.getDetails().toLowerCase().contains("required"));

        assertTrue(hasRequiredViolation, "Should detect missing required field");

        // Required violations should be HIGH severity
        boolean hasHighSeverity = findings.stream()
            .anyMatch(f -> f.getSeverity() == Severity.HIGH);

        assertTrue(hasHighSeverity, "Required field violations should be HIGH severity");
    }

    @Test
    void validate_withAdditionalProperties_shouldReturnMediumSeverity() throws Exception {
        String schema = """
                {
                  "type": "object",
                  "properties": {
                    "id": { "type": "integer" }
                  },
                  "additionalProperties": false
                }
                """;

        String instance = """
                {
                  "id": 123,
                  "extraField": "not allowed"
                }
                """;

        JsonContractValidator validator = new JsonContractValidator();
        List<ValidationFinding> findings = validator.validate(schema, instance);

        assertFalse(findings.isEmpty(), "Should have violations");

        // Should be MEDIUM severity for additional properties
        boolean hasMediumSeverity = findings.stream()
            .anyMatch(f -> f.getSeverity() == Severity.MEDIUM);

        assertTrue(hasMediumSeverity, "Additional properties should be MEDIUM severity");
    }

    @Test
    void validate_withValidInstance_shouldReturnNoViolations() throws Exception {
        String schema = """
                {
                  "type": "object",
                  "properties": {
                    "id": { "type": "integer" },
                    "name": { "type": "string" }
                  },
                  "required": ["id", "name"]
                }
                """;

        String instance = """
                {
                  "id": 123,
                  "name": "Test"
                }
                """;

        JsonContractValidator validator = new JsonContractValidator();
        List<ValidationFinding> findings = validator.validate(schema, instance);

        assertTrue(findings.isEmpty(), "Valid instance should have no violations");
    }

    @Test
    void validate_withInvalidSchema_shouldThrowException() {
        String invalidSchema = "{ invalid json }";
        String instance = """
                { "id": 123 }
                """;

        JsonContractValidator validator = new JsonContractValidator();

        assertThrows(Exception.class, () -> {
            validator.validate(invalidSchema, instance);
        }, "Should throw exception for invalid schema");
    }

    @Test
    void validate_withEnumViolation_shouldDetect() throws Exception {
        String schema = """
                {
                  "type": "object",
                  "properties": {
                    "status": {
                      "type": "string",
                      "enum": ["active", "inactive"]
                    }
                  }
                }
                """;

        String instance = """
                {
                  "status": "invalid-status"
                }
                """;

        JsonContractValidator validator = new JsonContractValidator();
        List<ValidationFinding> findings = validator.validate(schema, instance);

        assertFalse(findings.isEmpty(), "Should detect enum violation");
    }
}
