package active.validator;

import active.model.ApiEndpoint;
import active.validator.model.FuzzTestCase;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import model.ParameterSpec;

import java.util.*;

/**
 * Generates fuzzing test cases for API endpoints.
 * Creates malformed, edge-case, and invalid inputs to test API robustness.
 */
public final class FuzzingGenerator {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    // Common fuzzing payloads
    private static final List<String> SQL_INJECTION_PAYLOADS = List.of(
        "' OR '1'='1", "'; DROP TABLE users--", "1' UNION SELECT NULL--"
    );

    private static final List<String> XSS_PAYLOADS = List.of(
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>"
    );

    private static final List<String> COMMAND_INJECTION_PAYLOADS = List.of(
        "; ls -la", "| cat /etc/passwd", "&& whoami"
    );

    private static final List<String> SPECIAL_CHARACTERS = List.of(
        "!@#$%^&*()", "\\n\\r\\t", "../.../....", "../../etc/passwd", "<>&\"'"
    );

    private static final List<Object> BOUNDARY_VALUES = Arrays.asList(
        null, "", " ", "0", "-1", "999999999", Integer.MAX_VALUE, Integer.MIN_VALUE,
        Long.MAX_VALUE, Double.MAX_VALUE, Double.MIN_VALUE
    );

    /**
     * Generate fuzzing test cases for an endpoint.
     *
     * @param endpoint the endpoint to generate tests for
     * @param schema optional JSON schema for the endpoint
     * @return list of fuzzing test cases
     */
    public List<FuzzTestCase> generateFuzzTests(ApiEndpoint endpoint, Optional<JsonNode> schema) {
        List<FuzzTestCase> testCases = new ArrayList<>();

        // Generate parameter fuzzing tests
        testCases.addAll(generateParameterFuzzTests(endpoint));

        // Generate body fuzzing tests
        if (schema.isPresent() && shouldHaveBody(endpoint.getMethod())) {
            testCases.addAll(generateBodyFuzzTests(schema.get()));
        }

        // Generate type confusion tests
        testCases.addAll(generateTypeConfusionTests(endpoint, schema));

        // Generate injection tests
        testCases.addAll(generateInjectionTests(endpoint));

        // Generate boundary value tests
        testCases.addAll(generateBoundaryTests(endpoint));

        // Generate encoding tests
        testCases.addAll(generateEncodingTests(endpoint));

        return testCases;
    }

    /**
     * Generate fuzzing tests for query and path parameters.
     */
    private List<FuzzTestCase> generateParameterFuzzTests(ApiEndpoint endpoint) {
        List<FuzzTestCase> testCases = new ArrayList<>();

        for (ParameterSpec param : endpoint.getParameters()) {
            // Null values
            testCases.add(FuzzTestCase.builder()
                .name("Null parameter: " + param.getName())
                .description("Test with null value for " + param.getName())
                .category(FuzzTestCase.FuzzCategory.NULL_VALUES)
                .addParameter(param.getName(), null)
                .expectedBehavior(FuzzTestCase.ExpectedBehavior.GRACEFUL_ERROR)
                .build());

            // Empty values
            testCases.add(FuzzTestCase.builder()
                .name("Empty parameter: " + param.getName())
                .description("Test with empty string for " + param.getName())
                .category(FuzzTestCase.FuzzCategory.BOUNDARY_VALUE)
                .addParameter(param.getName(), "")
                .expectedBehavior(FuzzTestCase.ExpectedBehavior.GRACEFUL_ERROR)
                .build());

            // Very long values
            testCases.add(FuzzTestCase.builder()
                .name("Overflow parameter: " + param.getName())
                .description("Test with very long value for " + param.getName())
                .category(FuzzTestCase.FuzzCategory.OVERFLOW)
                .addParameter(param.getName(), "A".repeat(10000))
                .expectedBehavior(FuzzTestCase.ExpectedBehavior.GRACEFUL_ERROR)
                .build());

            // Special characters
            for (String specialChar : SPECIAL_CHARACTERS) {
                testCases.add(FuzzTestCase.builder()
                    .name("Special chars in " + param.getName() + ": " + truncate(specialChar))
                    .description("Test with special characters")
                    .category(FuzzTestCase.FuzzCategory.SPECIAL_CHARACTERS)
                    .addParameter(param.getName(), specialChar)
                    .expectedBehavior(FuzzTestCase.ExpectedBehavior.GRACEFUL_ERROR)
                    .build());
            }

            // SQL Injection
            for (String payload : SQL_INJECTION_PAYLOADS) {
                testCases.add(FuzzTestCase.builder()
                    .name("SQL injection in " + param.getName())
                    .description("Test SQL injection payload")
                    .category(FuzzTestCase.FuzzCategory.INJECTION)
                    .addParameter(param.getName(), payload)
                    .expectedBehavior(FuzzTestCase.ExpectedBehavior.REJECT_INVALID)
                    .build());
            }
        }

        return testCases;
    }

    /**
     * Generate fuzzing tests for request body.
     */
    private List<FuzzTestCase> generateBodyFuzzTests(JsonNode schema) {
        List<FuzzTestCase> testCases = new ArrayList<>();

        String schemaType = getSchemaType(schema);

        if ("object".equals(schemaType)) {
            // Empty object
            testCases.add(FuzzTestCase.builder()
                .name("Empty object body")
                .description("Send empty object as body")
                .category(FuzzTestCase.FuzzCategory.BOUNDARY_VALUE)
                .bodyPayload(objectMapper.createObjectNode())
                .expectedBehavior(FuzzTestCase.ExpectedBehavior.REJECT_INVALID)
                .build());

            // Missing required fields
            JsonNode properties = schema.get("properties");
            JsonNode required = schema.get("required");

            if (required != null && required.isArray() && properties != null) {
                ObjectNode incompleteBody = objectMapper.createObjectNode();

                testCases.add(FuzzTestCase.builder()
                    .name("Missing required fields")
                    .description("Body with missing required fields")
                    .category(FuzzTestCase.FuzzCategory.FORMAT_VIOLATION)
                    .bodyPayload(incompleteBody)
                    .expectedBehavior(FuzzTestCase.ExpectedBehavior.REJECT_INVALID)
                    .build());
            }

            // Extra unexpected fields
            if (schema.has("additionalProperties")) {
                boolean allowsAdditional = schema.get("additionalProperties").asBoolean(true);
                if (!allowsAdditional) {
                    ObjectNode bodyWithExtra = objectMapper.createObjectNode();
                    bodyWithExtra.put("unexpected_field", "value");
                    bodyWithExtra.put("another_unexpected", 123);

                    testCases.add(FuzzTestCase.builder()
                        .name("Unexpected additional fields")
                        .description("Body with fields not in schema")
                        .category(FuzzTestCase.FuzzCategory.FORMAT_VIOLATION)
                        .bodyPayload(bodyWithExtra)
                        .expectedBehavior(FuzzTestCase.ExpectedBehavior.REJECT_INVALID)
                        .build());
                }
            }

            // Null values for required fields
            if (required != null && properties != null) {
                ObjectNode nullBody = objectMapper.createObjectNode();
                for (JsonNode req : required) {
                    nullBody.putNull(req.asText());
                }

                testCases.add(FuzzTestCase.builder()
                    .name("Null values for required fields")
                    .description("Required fields set to null")
                    .category(FuzzTestCase.FuzzCategory.NULL_VALUES)
                    .bodyPayload(nullBody)
                    .expectedBehavior(FuzzTestCase.ExpectedBehavior.REJECT_INVALID)
                    .build());
            }

        } else if ("array".equals(schemaType)) {
            // Empty array
            testCases.add(FuzzTestCase.builder()
                .name("Empty array body")
                .description("Send empty array as body")
                .category(FuzzTestCase.FuzzCategory.ARRAY_MANIPULATION)
                .bodyPayload(objectMapper.createArrayNode())
                .expectedBehavior(FuzzTestCase.ExpectedBehavior.GRACEFUL_ERROR)
                .build());

            // Very large array
            ArrayNode largeArray = objectMapper.createArrayNode();
            for (int i = 0; i < 1000; i++) {
                largeArray.add(i);
            }

            testCases.add(FuzzTestCase.builder()
                .name("Very large array")
                .description("Array with many items")
                .category(FuzzTestCase.FuzzCategory.OVERFLOW)
                .bodyPayload(largeArray)
                .expectedBehavior(FuzzTestCase.ExpectedBehavior.NO_CRASH)
                .build());
        }

        // Invalid JSON
        testCases.add(FuzzTestCase.builder()
            .name("Invalid JSON")
            .description("Malformed JSON in body")
            .category(FuzzTestCase.FuzzCategory.FORMAT_VIOLATION)
            .bodyPayload("{invalid json")
            .expectedBehavior(FuzzTestCase.ExpectedBehavior.REJECT_INVALID)
            .build());

        return testCases;
    }

    /**
     * Generate type confusion tests.
     */
    private List<FuzzTestCase> generateTypeConfusionTests(ApiEndpoint endpoint, Optional<JsonNode> schema) {
        List<FuzzTestCase> testCases = new ArrayList<>();

        if (schema.isEmpty() || !schema.get().has("properties")) {
            return testCases;
        }

        JsonNode properties = schema.get().get("properties");
        ObjectNode confusedBody = objectMapper.createObjectNode();

        Iterator<Map.Entry<String, JsonNode>> fields = properties.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            String fieldName = field.getKey();
            String expectedType = getSchemaType(field.getValue());

            // Put wrong type
            switch (expectedType) {
                case "string":
                    confusedBody.put(fieldName, 12345); // Number instead of string
                    break;
                case "number":
                case "integer":
                    confusedBody.put(fieldName, "not a number"); // String instead of number
                    break;
                case "boolean":
                    confusedBody.put(fieldName, "true"); // String instead of boolean
                    break;
                case "array":
                    confusedBody.put(fieldName, "not an array"); // String instead of array
                    break;
                case "object":
                    confusedBody.put(fieldName, "not an object"); // String instead of object
                    break;
            }
        }

        if (confusedBody.size() > 0) {
            testCases.add(FuzzTestCase.builder()
                .name("Type confusion")
                .description("All fields with wrong types")
                .category(FuzzTestCase.FuzzCategory.TYPE_CONFUSION)
                .bodyPayload(confusedBody)
                .expectedBehavior(FuzzTestCase.ExpectedBehavior.REJECT_INVALID)
                .build());
        }

        return testCases;
    }

    /**
     * Generate injection attack tests.
     */
    private List<FuzzTestCase> generateInjectionTests(ApiEndpoint endpoint) {
        List<FuzzTestCase> testCases = new ArrayList<>();

        // SQL Injection in body
        ObjectNode sqlBody = objectMapper.createObjectNode();
        sqlBody.put("query", "'; DROP TABLE users--");

        testCases.add(FuzzTestCase.builder()
            .name("SQL injection in body")
            .description("SQL injection payload in body field")
            .category(FuzzTestCase.FuzzCategory.INJECTION)
            .bodyPayload(sqlBody)
            .expectedBehavior(FuzzTestCase.ExpectedBehavior.REJECT_INVALID)
            .build());

        // Command injection
        ObjectNode cmdBody = objectMapper.createObjectNode();
        cmdBody.put("command", "; cat /etc/passwd");

        testCases.add(FuzzTestCase.builder()
            .name("Command injection")
            .description("Command injection payload")
            .category(FuzzTestCase.FuzzCategory.INJECTION)
            .bodyPayload(cmdBody)
            .expectedBehavior(FuzzTestCase.ExpectedBehavior.REJECT_INVALID)
            .build());

        // XSS
        ObjectNode xssBody = objectMapper.createObjectNode();
        xssBody.put("content", "<script>alert('XSS')</script>");

        testCases.add(FuzzTestCase.builder()
            .name("XSS payload")
            .description("Cross-site scripting payload")
            .category(FuzzTestCase.FuzzCategory.INJECTION)
            .bodyPayload(xssBody)
            .expectedBehavior(FuzzTestCase.ExpectedBehavior.NO_CRASH)
            .build());

        return testCases;
    }

    /**
     * Generate boundary value tests.
     */
    private List<FuzzTestCase> generateBoundaryTests(ApiEndpoint endpoint) {
        List<FuzzTestCase> testCases = new ArrayList<>();

        for (Object boundaryValue : BOUNDARY_VALUES) {
            ObjectNode body = objectMapper.createObjectNode();
            if (boundaryValue == null) {
                body.putNull("value");
            } else if (boundaryValue instanceof String) {
                body.put("value", (String) boundaryValue);
            } else if (boundaryValue instanceof Integer) {
                body.put("value", (Integer) boundaryValue);
            } else if (boundaryValue instanceof Long) {
                body.put("value", (Long) boundaryValue);
            } else if (boundaryValue instanceof Double) {
                body.put("value", (Double) boundaryValue);
            }

            testCases.add(FuzzTestCase.builder()
                .name("Boundary value: " + boundaryValue)
                .description("Test with boundary value")
                .category(FuzzTestCase.FuzzCategory.BOUNDARY_VALUE)
                .bodyPayload(body)
                .expectedBehavior(FuzzTestCase.ExpectedBehavior.GRACEFUL_ERROR)
                .build());
        }

        return testCases;
    }

    /**
     * Generate encoding tests.
     */
    private List<FuzzTestCase> generateEncodingTests(ApiEndpoint endpoint) {
        List<FuzzTestCase> testCases = new ArrayList<>();

        // Unicode characters
        ObjectNode unicodeBody = objectMapper.createObjectNode();
        unicodeBody.put("text", "\u0000\u0001\u0002 unicode \uD83D\uDE00");

        testCases.add(FuzzTestCase.builder()
            .name("Unicode characters")
            .description("Test with Unicode and special chars")
            .category(FuzzTestCase.FuzzCategory.ENCODING)
            .bodyPayload(unicodeBody)
            .expectedBehavior(FuzzTestCase.ExpectedBehavior.NO_CRASH)
            .build());

        // Very long UTF-8 string
        ObjectNode utf8Body = objectMapper.createObjectNode();
        utf8Body.put("text", "å".repeat(1000));

        testCases.add(FuzzTestCase.builder()
            .name("Long UTF-8 string")
            .description("Very long UTF-8 encoded string")
            .category(FuzzTestCase.FuzzCategory.ENCODING)
            .bodyPayload(utf8Body)
            .expectedBehavior(FuzzTestCase.ExpectedBehavior.NO_CRASH)
            .build());

        return testCases;
    }

    // Helper methods

    private boolean shouldHaveBody(String method) {
        return method.equalsIgnoreCase("POST") ||
               method.equalsIgnoreCase("PUT") ||
               method.equalsIgnoreCase("PATCH");
    }

    private String getSchemaType(JsonNode schema) {
        if (schema.has("type")) {
            return schema.get("type").asText();
        }
        return "unknown";
    }

    private String truncate(String str) {
        return str.length() > 30 ? str.substring(0, 27) + "..." : str;
    }
}
