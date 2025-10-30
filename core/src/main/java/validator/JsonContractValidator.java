package validator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.*;
import model.Severity;
import model.ValidationFinding;

import java.util.*;

/**
 * Enhanced JSON schema contract validator with better error handling and classification.
 */
public final class JsonContractValidator {

    private final ObjectMapper mapper = new ObjectMapper();
    private final JsonSchemaFactory schemaFactory;

    public JsonContractValidator() {
        this.schemaFactory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7);
    }

    /**
     * Validates a JSON instance against a JSON schema.
     *
     * @param schemaJson the JSON schema as a string
     * @param instanceJson the JSON instance to validate
     * @return list of validation findings
     * @throws Exception if parsing fails
     */
    public List<ValidationFinding> validate(String schemaJson, String instanceJson) throws Exception {
        Objects.requireNonNull(schemaJson, "Schema JSON cannot be null");
        Objects.requireNonNull(instanceJson, "Instance JSON cannot be null");

        JsonNode schemaNode;
        JsonNode instanceNode;

        try {
            schemaNode = mapper.readTree(schemaJson);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid schema JSON: " + e.getMessage(), e);
        }

        try {
            instanceNode = mapper.readTree(instanceJson);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid instance JSON: " + e.getMessage(), e);
        }

        return validateNodes(schemaNode, instanceNode);
    }

    /**
     * Validates a JSON instance node against a schema node.
     *
     * @param schemaNode the schema as JsonNode
     * @param instanceNode the instance as JsonNode
     * @return list of validation findings
     */
    public List<ValidationFinding> validateNodes(JsonNode schemaNode, JsonNode instanceNode) {
        Objects.requireNonNull(schemaNode, "Schema node cannot be null");
        Objects.requireNonNull(instanceNode, "Instance node cannot be null");

        List<ValidationFinding> findings = new ArrayList<>();

        try {
            JsonSchema jsonSchema = schemaFactory.getSchema(schemaNode);
            Set<ValidationMessage> messages = jsonSchema.validate(instanceNode);

            for (ValidationMessage msg : messages) {
                Severity severity = classifyViolation(msg);
                String path = msg.getEvaluationPath() != null
                    ? msg.getEvaluationPath().toString()
                    : msg.getInstanceLocation().toString();

                Map<String, Object> metadata = new HashMap<>();
                metadata.put("schemaPath", msg.getSchemaLocation() != null ? msg.getSchemaLocation().toString() : "");
                metadata.put("violationType", msg.getType());
                metadata.put("arguments", msg.getArguments());

                findings.add(new ValidationFinding(
                    severity,
                    ValidationFinding.FindingCategory.CONTRACT,
                    "JSON_SCHEMA_VIOLATION",
                    path,
                    null,
                    msg.getMessage(),
                    getRecommendation(msg),
                    metadata
                ));
            }
        } catch (Exception e) {
            findings.add(new ValidationFinding(
                Severity.CRITICAL,
                ValidationFinding.FindingCategory.CONTRACT,
                "SCHEMA_VALIDATION_ERROR",
                null,
                null,
                "Schema validation failed: " + e.getMessage(),
                "Ensure both schema and instance are valid JSON and the schema is well-formed.",
                Map.of("error", e.getClass().getSimpleName())
            ));
        }

        return findings;
    }

    /**
     * Classifies a validation message into a severity level.
     */
    private Severity classifyViolation(ValidationMessage msg) {
        String message = msg.getMessage().toLowerCase();
        String type = msg.getType() != null ? msg.getType().toLowerCase() : "";

        if (type.contains("type") && message.contains("is not of type")) {
            return Severity.HIGH;
        }

        if (message.contains("required") || message.contains("is missing")) {
            return Severity.HIGH;
        }

        if (type.contains("required")) {
            return Severity.HIGH;
        }

        if (message.contains("additional properties") || type.contains("additionalproperties")) {
            return Severity.MEDIUM;
        }

        if (message.contains("enum") || message.contains("does not have a value in the enumeration")) {
            return Severity.MEDIUM;
        }

        if (message.contains("pattern") || type.contains("pattern")) {
            return Severity.MEDIUM;
        }

        if (message.contains("format")) {
            return Severity.MEDIUM;
        }

        if (message.contains("minlength") || message.contains("maxlength")) {
            return Severity.LOW;
        }

        if (message.contains("minimum") || message.contains("maximum")) {
            return Severity.LOW;
        }

        return Severity.MEDIUM;
    }

    /**
     * Provides contextual recommendations based on validation message.
     */
    private String getRecommendation(ValidationMessage msg) {
        String message = msg.getMessage().toLowerCase();
        String type = msg.getType() != null ? msg.getType().toLowerCase() : "";

        if (type.contains("type") || message.contains("is not of type")) {
            return "Ensure the field has the correct data type as specified in the schema.";
        }

        if (message.contains("required") || message.contains("is missing")) {
            return "Add the required field(s) to the JSON instance.";
        }

        if (message.contains("additional properties")) {
            return "Remove unexpected properties or update the schema to allow them.";
        }

        if (message.contains("enum")) {
            return "Use one of the allowed enumeration values specified in the schema.";
        }

        if (message.contains("pattern")) {
            return "Ensure the value matches the required pattern/regex.";
        }

        if (message.contains("format")) {
            return "Ensure the value conforms to the specified format (e.g., email, date, uri).";
        }

        if (message.contains("minlength") || message.contains("maxlength")) {
            return "Adjust the string length to meet the schema constraints.";
        }

        if (message.contains("minimum") || message.contains("maximum")) {
            return "Adjust the numeric value to be within the allowed range.";
        }

        return "Ensure the JSON instance conforms to the schema definition.";
    }
}
