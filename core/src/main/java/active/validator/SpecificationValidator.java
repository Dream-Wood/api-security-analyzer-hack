package active.validator;

import active.model.TestResponse;
import active.validator.model.Divergence;
import active.validator.model.DivergenceType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;
import java.util.logging.Logger;

/**
 * Validates API responses against their OpenAPI specification.
 * Detects divergences between actual behavior and documented contract.
 */
public final class SpecificationValidator {
    private static final Logger logger = Logger.getLogger(SpecificationValidator.class.getName());
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Validate response against specification schema.
     *
     * @param response the actual HTTP response
     * @param expectedSchema the JSON schema from OpenAPI spec
     * @param statusCode the status code to validate
     * @return list of detected divergences
     */
    public List<Divergence> validateResponse(
        TestResponse response,
        JsonNode expectedSchema,
        int statusCode
    ) {
        List<Divergence> divergences = new ArrayList<>();

        // Check status code
        if (response.getStatusCode() != statusCode) {
            divergences.add(Divergence.builder()
                .type(DivergenceType.UNEXPECTED_STATUS_CODE)
                .message(String.format("Expected status code %d but got %d", statusCode, response.getStatusCode()))
                .expectedValue(statusCode)
                .actualValue(response.getStatusCode())
                .severity(Divergence.Severity.HIGH)
                .build());
        }

        // Validate response body if present
        if (response.getBody() != null && !response.getBody().isBlank()) {
            try {
                JsonNode actualBody = objectMapper.readTree(response.getBody());
                divergences.addAll(validateSchema(actualBody, expectedSchema, ""));
            } catch (Exception e) {
                logger.warning("Failed to parse response body: " + e.getMessage());
                divergences.add(Divergence.builder()
                    .type(DivergenceType.SCHEMA_VIOLATION)
                    .message("Response body is not valid JSON: " + e.getMessage())
                    .severity(Divergence.Severity.HIGH)
                    .build());
            }
        } else if (expectedSchema != null && !expectedSchema.isNull()) {
            // Expected body but got none
            divergences.add(Divergence.builder()
                .type(DivergenceType.SCHEMA_VIOLATION)
                .message("Expected response body according to specification but got empty response")
                .severity(Divergence.Severity.MEDIUM)
                .build());
        }

        // Validate content type
        divergences.addAll(validateContentType(response, expectedSchema));

        return divergences;
    }

    /**
     * Recursively validate JSON against schema.
     */
    private List<Divergence> validateSchema(JsonNode actual, JsonNode schema, String path) {
        List<Divergence> divergences = new ArrayList<>();

        if (schema == null || schema.isNull()) {
            return divergences;
        }

        String schemaType = getSchemaType(schema);

        if (schemaType != null) {
            divergences.addAll(validateType(actual, schemaType, path));

            switch (schemaType) {
                case "object":
                    divergences.addAll(validateObject(actual, schema, path));
                    break;
                case "array":
                    divergences.addAll(validateArray(actual, schema, path));
                    break;
                case "string":
                    divergences.addAll(validateString(actual, schema, path));
                    break;
                case "number":
                case "integer":
                    divergences.addAll(validateNumber(actual, schema, path));
                    break;
            }
        }

        // Check enum values
        if (schema.has("enum")) {
            divergences.addAll(validateEnum(actual, schema, path));
        }

        return divergences;
    }

    /**
     * Validate object properties.
     */
    private List<Divergence> validateObject(JsonNode actual, JsonNode schema, String path) {
        List<Divergence> divergences = new ArrayList<>();

        if (!actual.isObject()) {
            return divergences; // Type mismatch already reported
        }

        JsonNode properties = schema.get("properties");
        JsonNode required = schema.get("required");
        boolean additionalPropertiesAllowed = isAdditionalPropertiesAllowed(schema);

        // Check required fields
        if (required != null && required.isArray()) {
            for (JsonNode requiredField : required) {
                String fieldName = requiredField.asText();
                if (!actual.has(fieldName)) {
                    divergences.add(Divergence.builder()
                        .type(DivergenceType.MISSING_REQUIRED_FIELD)
                        .path(path)
                        .field(fieldName)
                        .message(String.format("Required field '%s' is missing", fieldName))
                        .severity(Divergence.Severity.HIGH)
                        .build());
                } else if (actual.get(fieldName).isNull()) {
                    divergences.add(Divergence.builder()
                        .type(DivergenceType.NULL_REQUIRED_FIELD)
                        .path(path)
                        .field(fieldName)
                        .message(String.format("Required field '%s' is null", fieldName))
                        .severity(Divergence.Severity.HIGH)
                        .build());
                }
            }
        }

        // Validate defined properties
        if (properties != null && properties.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = properties.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String fieldName = field.getKey();
                JsonNode fieldSchema = field.getValue();

                if (actual.has(fieldName)) {
                    String fieldPath = path.isEmpty() ? fieldName : path + "." + fieldName;
                    divergences.addAll(validateSchema(actual.get(fieldName), fieldSchema, fieldPath));
                }
            }
        }

        // Check for unexpected fields
        if (!additionalPropertiesAllowed) {
            Set<String> definedFields = new HashSet<>();
            if (properties != null && properties.isObject()) {
                properties.fieldNames().forEachRemaining(definedFields::add);
            }

            Iterator<String> actualFields = actual.fieldNames();
            while (actualFields.hasNext()) {
                String fieldName = actualFields.next();
                if (!definedFields.contains(fieldName)) {
                    divergences.add(Divergence.builder()
                        .type(DivergenceType.ADDITIONAL_PROPERTIES_FORBIDDEN)
                        .path(path)
                        .field(fieldName)
                        .message(String.format("Unexpected field '%s' (additionalProperties: false)", fieldName))
                        .severity(Divergence.Severity.MEDIUM)
                        .build());
                }
            }
        } else if (properties != null) {
            // Just report unexpected fields as informational
            Set<String> definedFields = new HashSet<>();
            properties.fieldNames().forEachRemaining(definedFields::add);

            Iterator<String> actualFields = actual.fieldNames();
            while (actualFields.hasNext()) {
                String fieldName = actualFields.next();
                if (!definedFields.contains(fieldName)) {
                    divergences.add(Divergence.builder()
                        .type(DivergenceType.UNEXPECTED_FIELD)
                        .path(path)
                        .field(fieldName)
                        .message(String.format("Field '%s' not defined in specification", fieldName))
                        .severity(Divergence.Severity.LOW)
                        .build());
                }
            }
        }

        return divergences;
    }

    /**
     * Validate array items.
     */
    private List<Divergence> validateArray(JsonNode actual, JsonNode schema, String path) {
        List<Divergence> divergences = new ArrayList<>();

        if (!actual.isArray()) {
            return divergences; // Type mismatch already reported
        }

        JsonNode items = schema.get("items");
        if (items != null) {
            for (int i = 0; i < actual.size(); i++) {
                String itemPath = path + "[" + i + "]";
                divergences.addAll(validateSchema(actual.get(i), items, itemPath));
            }
        }

        // Validate array constraints
        if (schema.has("minItems")) {
            int minItems = schema.get("minItems").asInt();
            if (actual.size() < minItems) {
                divergences.add(Divergence.builder()
                    .type(DivergenceType.SCHEMA_VIOLATION)
                    .path(path)
                    .message(String.format("Array has %d items, minimum is %d", actual.size(), minItems))
                    .severity(Divergence.Severity.MEDIUM)
                    .build());
            }
        }

        if (schema.has("maxItems")) {
            int maxItems = schema.get("maxItems").asInt();
            if (actual.size() > maxItems) {
                divergences.add(Divergence.builder()
                    .type(DivergenceType.SCHEMA_VIOLATION)
                    .path(path)
                    .message(String.format("Array has %d items, maximum is %d", actual.size(), maxItems))
                    .severity(Divergence.Severity.MEDIUM)
                    .build());
            }
        }

        return divergences;
    }

    /**
     * Validate string constraints.
     */
    private List<Divergence> validateString(JsonNode actual, JsonNode schema, String path) {
        List<Divergence> divergences = new ArrayList<>();

        if (!actual.isTextual()) {
            return divergences; // Type mismatch already reported
        }

        String value = actual.asText();

        // Validate pattern
        if (schema.has("pattern")) {
            String pattern = schema.get("pattern").asText();
            if (!value.matches(pattern)) {
                divergences.add(Divergence.builder()
                    .type(DivergenceType.SCHEMA_VIOLATION)
                    .path(path)
                    .message(String.format("String '%s' doesn't match pattern '%s'", truncate(value), pattern))
                    .severity(Divergence.Severity.MEDIUM)
                    .build());
            }
        }

        // Validate length
        if (schema.has("minLength")) {
            int minLength = schema.get("minLength").asInt();
            if (value.length() < minLength) {
                divergences.add(Divergence.builder()
                    .type(DivergenceType.SCHEMA_VIOLATION)
                    .path(path)
                    .message(String.format("String length %d is less than minimum %d", value.length(), minLength))
                    .severity(Divergence.Severity.MEDIUM)
                    .build());
            }
        }

        if (schema.has("maxLength")) {
            int maxLength = schema.get("maxLength").asInt();
            if (value.length() > maxLength) {
                divergences.add(Divergence.builder()
                    .type(DivergenceType.SCHEMA_VIOLATION)
                    .path(path)
                    .message(String.format("String length %d exceeds maximum %d", value.length(), maxLength))
                    .severity(Divergence.Severity.MEDIUM)
                    .build());
            }
        }

        return divergences;
    }

    /**
     * Validate number constraints.
     */
    private List<Divergence> validateNumber(JsonNode actual, JsonNode schema, String path) {
        List<Divergence> divergences = new ArrayList<>();

        if (!actual.isNumber()) {
            return divergences; // Type mismatch already reported
        }

        double value = actual.asDouble();

        if (schema.has("minimum")) {
            double minimum = schema.get("minimum").asDouble();
            if (value < minimum) {
                divergences.add(Divergence.builder()
                    .type(DivergenceType.SCHEMA_VIOLATION)
                    .path(path)
                    .message(String.format("Value %f is less than minimum %f", value, minimum))
                    .severity(Divergence.Severity.MEDIUM)
                    .build());
            }
        }

        if (schema.has("maximum")) {
            double maximum = schema.get("maximum").asDouble();
            if (value > maximum) {
                divergences.add(Divergence.builder()
                    .type(DivergenceType.SCHEMA_VIOLATION)
                    .path(path)
                    .message(String.format("Value %f exceeds maximum %f", value, maximum))
                    .severity(Divergence.Severity.MEDIUM)
                    .build());
            }
        }

        return divergences;
    }

    /**
     * Validate enum values.
     */
    private List<Divergence> validateEnum(JsonNode actual, JsonNode schema, String path) {
        List<Divergence> divergences = new ArrayList<>();

        JsonNode enumValues = schema.get("enum");
        if (enumValues != null && enumValues.isArray()) {
            boolean found = false;
            for (JsonNode enumValue : enumValues) {
                if (enumValue.equals(actual)) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                divergences.add(Divergence.builder()
                    .type(DivergenceType.INVALID_ENUM_VALUE)
                    .path(path)
                    .message(String.format("Value '%s' is not in enum", actual.asText()))
                    .actualValue(actual.asText())
                    .expectedValue(enumValues.toString())
                    .severity(Divergence.Severity.HIGH)
                    .build());
            }
        }

        return divergences;
    }

    /**
     * Validate type matches.
     */
    private List<Divergence> validateType(JsonNode actual, String expectedType, String path) {
        List<Divergence> divergences = new ArrayList<>();

        String actualType = getActualType(actual);

        if (!isTypeCompatible(actualType, expectedType)) {
            divergences.add(Divergence.builder()
                .type(DivergenceType.TYPE_MISMATCH)
                .path(path)
                .message(String.format("Expected type '%s' but got '%s'", expectedType, actualType))
                .expectedValue(expectedType)
                .actualValue(actualType)
                .severity(Divergence.Severity.HIGH)
                .build());
        }

        return divergences;
    }

    /**
     * Validate content type.
     */
    private List<Divergence> validateContentType(TestResponse response, JsonNode schema) {
        List<Divergence> divergences = new ArrayList<>();

        Optional<String> contentType = response.getHeader("Content-Type");
        if (contentType.isPresent() && schema != null) {
            String ct = contentType.get().toLowerCase();
            // For now, just check if it's JSON when we expect JSON
            if (!ct.contains("application/json") && !ct.contains("application/problem+json")) {
                divergences.add(Divergence.builder()
                    .type(DivergenceType.CONTENT_TYPE_MISMATCH)
                    .message("Expected JSON content type but got: " + ct)
                    .actualValue(ct)
                    .expectedValue("application/json")
                    .severity(Divergence.Severity.MEDIUM)
                    .build());
            }
        }

        return divergences;
    }

    // Helper methods

    private String getSchemaType(JsonNode schema) {
        if (schema.has("type")) {
            return schema.get("type").asText();
        }
        return null;
    }

    private String getActualType(JsonNode node) {
        if (node.isObject()) return "object";
        if (node.isArray()) return "array";
        if (node.isTextual()) return "string";
        if (node.isInt()) return "integer";
        if (node.isNumber()) return "number";
        if (node.isBoolean()) return "boolean";
        if (node.isNull()) return "null";
        return "unknown";
    }

    private boolean isTypeCompatible(String actualType, String expectedType) {
        if (actualType.equals(expectedType)) {
            return true;
        }
        // Integer is compatible with number
        if (expectedType.equals("number") && actualType.equals("integer")) {
            return true;
        }
        return false;
    }

    private boolean isAdditionalPropertiesAllowed(JsonNode schema) {
        if (!schema.has("additionalProperties")) {
            return true; // Default is true
        }
        JsonNode additionalProps = schema.get("additionalProperties");
        if (additionalProps.isBoolean()) {
            return additionalProps.asBoolean();
        }
        return true; // If it's an object schema, additional properties are allowed
    }

    private String truncate(String str) {
        return str.length() > 50 ? str.substring(0, 47) + "..." : str;
    }
}
