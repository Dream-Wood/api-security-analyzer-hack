package active.validator;

import active.model.ApiEndpoint;
import active.model.TestRequest;
import active.model.TestResponse;
import active.http.HttpClient;
import active.validator.model.Divergence;
import active.validator.model.DivergenceType;
import com.fasterxml.jackson.databind.JsonNode;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;
import java.util.logging.Logger;

/**
 * Detects divergences between API specification and actual implementation.
 * Identifies undocumented endpoints, missing fields, type mismatches, etc.
 */
public final class DivergenceDetector {
    private static final Logger logger = Logger.getLogger(DivergenceDetector.class.getName());
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final OpenAPI openAPI;
    private final SpecificationValidator specValidator;

    public DivergenceDetector(OpenAPI openAPI) {
        this.openAPI = Objects.requireNonNull(openAPI, "OpenAPI cannot be null");
        this.specValidator = new SpecificationValidator();
    }

    /**
     * Check if an endpoint is documented in the specification.
     *
     * @param endpoint the endpoint to check
     * @return true if the endpoint is documented
     */
    public boolean isEndpointDocumented(ApiEndpoint endpoint) {
        if (openAPI.getPaths() == null) {
            return false;
        }

        PathItem pathItem = openAPI.getPaths().get(endpoint.getPath());
        if (pathItem == null) {
            // Try to match with path parameters (e.g., /users/{id})
            pathItem = findMatchingPath(endpoint.getPath());
        }

        if (pathItem == null) {
            return false;
        }

        return getOperation(pathItem, endpoint.getMethod()) != null;
    }

    /**
     * Detect divergences by comparing actual response with specification.
     *
     * @param endpoint the endpoint being tested
     * @param response the actual response received
     * @return list of detected divergences
     */
    public List<Divergence> detectDivergences(ApiEndpoint endpoint, TestResponse response) {
        List<Divergence> divergences = new ArrayList<>();

        // Check if endpoint is documented
        if (!isEndpointDocumented(endpoint)) {
            divergences.add(Divergence.builder()
                .type(DivergenceType.UNDOCUMENTED_ENDPOINT)
                .path(endpoint.getPath())
                .message(String.format("Endpoint %s %s is not documented in the API specification",
                    endpoint.getMethod(), endpoint.getPath()))
                .severity(Divergence.Severity.HIGH)
                .addMetadata("method", endpoint.getMethod())
                .addMetadata("path", endpoint.getPath())
                .build());
            return divergences; // Can't validate further without spec
        }

        // Get expected schema for this response
        Optional<JsonNode> expectedSchema = getExpectedResponseSchema(endpoint, response.getStatusCode());

        if (expectedSchema.isEmpty()) {
            // Status code not documented
            divergences.add(Divergence.builder()
                .type(DivergenceType.UNEXPECTED_STATUS_CODE)
                .path(endpoint.getPath())
                .message(String.format("Status code %d is not documented for %s %s",
                    response.getStatusCode(), endpoint.getMethod(), endpoint.getPath()))
                .actualValue(response.getStatusCode())
                .severity(response.getStatusCode() >= 500 ? Divergence.Severity.HIGH : Divergence.Severity.MEDIUM)
                .build());
        } else {
            // Validate response against schema
            divergences.addAll(specValidator.validateResponse(
                response,
                expectedSchema.get(),
                response.getStatusCode()
            ));
        }

        return divergences;
    }

    /**
     * Probe an endpoint to detect undocumented behavior.
     *
     * @param endpoint the endpoint to probe
     * @param httpClient the HTTP client
     * @return list of detected divergences
     */
    public List<Divergence> probeEndpoint(ApiEndpoint endpoint, HttpClient httpClient) {
        List<Divergence> divergences = new ArrayList<>();

        try {
            // Test basic GET request
            TestRequest request = TestRequest.builder()
                .url(buildUrl(endpoint))
                .method(endpoint.getMethod())
                .build();

            TestResponse response = httpClient.execute(request);

            divergences.addAll(detectDivergences(endpoint, response));

        } catch (Exception e) {
            logger.warning("Failed to probe endpoint: " + e.getMessage());
            divergences.add(Divergence.builder()
                .type(DivergenceType.SCHEMA_VIOLATION)
                .path(endpoint.getPath())
                .message("Failed to probe endpoint: " + e.getMessage())
                .severity(Divergence.Severity.MEDIUM)
                .build());
        }

        return divergences;
    }

    /**
     * Discover undocumented endpoints by comparing actual implementation with spec.
     *
     * @param actualEndpoints list of actual endpoints discovered
     * @return list of undocumented endpoints
     */
    public List<Divergence> findUndocumentedEndpoints(List<ApiEndpoint> actualEndpoints) {
        List<Divergence> divergences = new ArrayList<>();

        for (ApiEndpoint endpoint : actualEndpoints) {
            if (!isEndpointDocumented(endpoint)) {
                divergences.add(Divergence.builder()
                    .type(DivergenceType.UNDOCUMENTED_ENDPOINT)
                    .path(endpoint.getPath())
                    .message(String.format("Endpoint %s %s exists but is not documented",
                        endpoint.getMethod(), endpoint.getPath()))
                    .severity(Divergence.Severity.HIGH)
                    .addMetadata("method", endpoint.getMethod())
                    .addMetadata("operationId", endpoint.getOperationId())
                    .build());
            }
        }

        return divergences;
    }

    /**
     * Analyze response consistency across multiple calls.
     *
     * @param responses list of responses from the same endpoint
     * @return divergences related to inconsistent responses
     */
    public List<Divergence> analyzeResponseConsistency(List<TestResponse> responses) {
        List<Divergence> divergences = new ArrayList<>();

        if (responses.size() < 2) {
            return divergences;
        }

        // Check if response schemas are consistent
        Set<String> schemas = new HashSet<>();
        for (TestResponse response : responses) {
            if (response.getBody() != null && !response.getBody().isBlank()) {
                try {
                    JsonNode json = objectMapper.readTree(response.getBody());
                    String schema = extractSchemaSignature(json);
                    schemas.add(schema);
                } catch (Exception e) {
                    // Ignore parsing errors
                }
            }
        }

        if (schemas.size() > 1) {
            divergences.add(Divergence.builder()
                .type(DivergenceType.SCHEMA_VIOLATION)
                .message("Response schema is inconsistent across multiple calls")
                .severity(Divergence.Severity.HIGH)
                .addMetadata("uniqueSchemas", schemas.size())
                .addMetadata("totalCalls", responses.size())
                .build());
        }

        return divergences;
    }

    // Helper methods

    private PathItem findMatchingPath(String actualPath) {
        if (openAPI.getPaths() == null) {
            return null;
        }

        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String specPath = entry.getKey();
            if (pathsMatch(actualPath, specPath)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private boolean pathsMatch(String actualPath, String specPath) {
        // Simple path matching with parameter substitution
        String[] actualParts = actualPath.split("/");
        String[] specParts = specPath.split("/");

        if (actualParts.length != specParts.length) {
            return false;
        }

        for (int i = 0; i < actualParts.length; i++) {
            String specPart = specParts[i];
            String actualPart = actualParts[i];

            // Check if spec part is a parameter (e.g., {id})
            if (specPart.startsWith("{") && specPart.endsWith("}")) {
                continue; // Parameter can match any value
            }

            // Must match exactly
            if (!specPart.equals(actualPart)) {
                return false;
            }
        }

        return true;
    }

    private Operation getOperation(PathItem pathItem, String method) {
        return switch (method.toUpperCase()) {
            case "GET" -> pathItem.getGet();
            case "POST" -> pathItem.getPost();
            case "PUT" -> pathItem.getPut();
            case "DELETE" -> pathItem.getDelete();
            case "PATCH" -> pathItem.getPatch();
            case "HEAD" -> pathItem.getHead();
            case "OPTIONS" -> pathItem.getOptions();
            default -> null;
        };
    }

    private Optional<JsonNode> getExpectedResponseSchema(ApiEndpoint endpoint, int statusCode) {
        PathItem pathItem = openAPI.getPaths().get(endpoint.getPath());
        if (pathItem == null) {
            pathItem = findMatchingPath(endpoint.getPath());
        }

        if (pathItem == null) {
            return Optional.empty();
        }

        Operation operation = getOperation(pathItem, endpoint.getMethod());
        if (operation == null || operation.getResponses() == null) {
            return Optional.empty();
        }

        // Try exact status code match
        String statusCodeStr = String.valueOf(statusCode);
        ApiResponse apiResponse = operation.getResponses().get(statusCodeStr);

        // Try default response
        if (apiResponse == null) {
            apiResponse = operation.getResponses().get("default");
        }

        // Try status code range (e.g., "2XX")
        if (apiResponse == null) {
            String range = statusCodeStr.charAt(0) + "XX";
            apiResponse = operation.getResponses().get(range);
        }

        if (apiResponse == null || apiResponse.getContent() == null) {
            return Optional.empty();
        }

        // Get JSON schema
        MediaType mediaType = apiResponse.getContent().get("application/json");
        if (mediaType == null) {
            mediaType = apiResponse.getContent().get("*/*");
        }

        if (mediaType == null || mediaType.getSchema() == null) {
            return Optional.empty();
        }

        try {
            // Convert OpenAPI Schema to JsonNode
            String schemaJson = objectMapper.writeValueAsString(mediaType.getSchema());
            JsonNode schemaNode = objectMapper.readTree(schemaJson);
            return Optional.of(schemaNode);
        } catch (Exception e) {
            logger.warning("Failed to convert schema: " + e.getMessage());
            return Optional.empty();
        }
    }

    private String buildUrl(ApiEndpoint endpoint) {
        // This is a simplified version - in practice, you'd need the base URL
        return endpoint.getPath();
    }

    private String extractSchemaSignature(JsonNode json) {
        // Create a simple signature based on field names and types
        StringBuilder signature = new StringBuilder();
        if (json.isObject()) {
            List<String> fields = new ArrayList<>();
            json.fieldNames().forEachRemaining(fields::add);
            Collections.sort(fields);
            for (String field : fields) {
                JsonNode value = json.get(field);
                signature.append(field).append(":").append(getNodeType(value)).append(",");
            }
        } else if (json.isArray()) {
            signature.append("array[");
            if (json.size() > 0) {
                signature.append(extractSchemaSignature(json.get(0)));
            }
            signature.append("]");
        } else {
            signature.append(getNodeType(json));
        }
        return signature.toString();
    }

    private String getNodeType(JsonNode node) {
        if (node.isObject()) return "object";
        if (node.isArray()) return "array";
        if (node.isTextual()) return "string";
        if (node.isInt()) return "integer";
        if (node.isNumber()) return "number";
        if (node.isBoolean()) return "boolean";
        if (node.isNull()) return "null";
        return "unknown";
    }
}
