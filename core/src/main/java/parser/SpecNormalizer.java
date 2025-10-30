package parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import model.OperationSpec;
import model.ParameterSpec;

import java.util.*;

/**
 * Enhanced normalizer that converts OpenAPI to internal OperationSpec format
 * with comprehensive metadata extraction.
 */
public final class SpecNormalizer {

    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Normalizes OpenAPI specification to list of OperationSpec objects.
     *
     * @param openAPI the OpenAPI specification
     * @return list of normalized operations
     */
    public List<OperationSpec> normalize(OpenAPI openAPI) {
        Objects.requireNonNull(openAPI, "openAPI must not be null");

        if (openAPI.getPaths() == null) {
            return Collections.emptyList();
        }

        List<OperationSpec> result = new ArrayList<>();

        for (Map.Entry<String, PathItem> pathEntry : openAPI.getPaths().entrySet()) {
            String path = pathEntry.getKey();
            PathItem pathItem = pathEntry.getValue();
            if (pathItem == null) continue;

            // Process each HTTP method
            Map<PathItem.HttpMethod, Operation> ops = pathItem.readOperationsMap();
            for (Map.Entry<PathItem.HttpMethod, Operation> opEntry : ops.entrySet()) {
                PathItem.HttpMethod httpMethod = opEntry.getKey();
                Operation operation = opEntry.getValue();
                if (operation == null) continue;

                OperationSpec spec = normalizeOperation(path, httpMethod, operation, openAPI);
                result.add(spec);
            }
        }

        return result;
    }

    private OperationSpec normalizeOperation(String path, PathItem.HttpMethod httpMethod,
                                            Operation operation, OpenAPI openAPI) {
        String method = httpMethod.name().toUpperCase(Locale.ROOT);
        String operationId = operation.getOperationId();
        String summary = operation.getSummary();
        String description = operation.getDescription();
        boolean deprecated = Boolean.TRUE.equals(operation.getDeprecated());

        // Extract responses
        Map<String, JsonNode> responsesMap = extractResponses(operation);

        // Extract request body schema
        Optional<JsonNode> requestSchema = extractRequestBody(operation);

        // Extract parameters
        List<ParameterSpec> parameters = extractParameters(operation);

        // Extract security schemes
        List<String> securitySchemes = extractSecuritySchemes(operation, openAPI);

        // Extract tags
        List<String> tags = operation.getTags() != null
            ? new ArrayList<>(operation.getTags())
            : Collections.emptyList();

        return OperationSpec.builder()
            .path(path)
            .method(method)
            .operationId(operationId)
            .summary(summary)
            .description(description)
            .responsesByCode(responsesMap)
            .requestBodySchema(requestSchema)
            .parameters(parameters)
            .securitySchemes(securitySchemes)
            .tags(tags)
            .deprecated(deprecated)
            .build();
    }

    private Map<String, JsonNode> extractResponses(Operation operation) {
        Map<String, JsonNode> responsesMap = new LinkedHashMap<>();

        if (operation.getResponses() == null) {
            return responsesMap;
        }

        for (Map.Entry<String, ApiResponse> r : operation.getResponses().entrySet()) {
            String code = r.getKey();
            ApiResponse apiResponse = r.getValue();
            JsonNode schemaNode = null;

            if (apiResponse != null && apiResponse.getContent() != null) {
                // Prefer application/json if available
                MediaType mediaType = apiResponse.getContent().get("application/json");
                if (mediaType == null) {
                    // Take first available media type
                    mediaType = apiResponse.getContent().values().stream()
                        .findFirst()
                        .orElse(null);
                }

                if (mediaType != null && mediaType.getSchema() != null) {
                    Schema<?> schema = mediaType.getSchema();
                    schemaNode = mapper.convertValue(schema, JsonNode.class);
                }
            }

            responsesMap.put(code, schemaNode);
        }

        return responsesMap;
    }

    private Optional<JsonNode> extractRequestBody(Operation operation) {
        RequestBody requestBody = operation.getRequestBody();
        if (requestBody == null || requestBody.getContent() == null) {
            return Optional.empty();
        }

        MediaType mediaType = requestBody.getContent().get("application/json");
        if (mediaType == null) {
            // Take first available media type
            mediaType = requestBody.getContent().values().stream()
                .findFirst()
                .orElse(null);
        }

        if (mediaType != null && mediaType.getSchema() != null) {
            Schema<?> schema = mediaType.getSchema();
            return Optional.of(mapper.convertValue(schema, JsonNode.class));
        }

        return Optional.empty();
    }

    private List<ParameterSpec> extractParameters(Operation operation) {
        List<ParameterSpec> parameters = new ArrayList<>();

        if (operation.getParameters() == null) {
            return parameters;
        }

        for (Parameter param : operation.getParameters()) {
            if (param == null) continue;

            String name = param.getName();
            ParameterSpec paramSpec = getParameterSpec(param, name);
            parameters.add(paramSpec);
        }

        return parameters;
    }

    private ParameterSpec getParameterSpec(Parameter param, String name) {
        ParameterSpec.ParameterLocation location = mapParameterLocation(param.getIn());
        boolean required = Boolean.TRUE.equals(param.getRequired());
        String type = param.getSchema() != null ? param.getSchema().getType() : null;
        String description = param.getDescription();
        Object defaultValue = param.getSchema() != null ? param.getSchema().getDefault() : null;

        return new ParameterSpec(name, location, required, type, description, defaultValue);
    }

    private ParameterSpec.ParameterLocation mapParameterLocation(String in) {
        if (in == null) {
            return ParameterSpec.ParameterLocation.QUERY;
        }
        return switch (in.toLowerCase()) {
            case "path" -> ParameterSpec.ParameterLocation.PATH;
            case "header" -> ParameterSpec.ParameterLocation.HEADER;
            case "cookie" -> ParameterSpec.ParameterLocation.COOKIE;
            default -> ParameterSpec.ParameterLocation.QUERY;
        };
    }

    private List<String> extractSecuritySchemes(Operation operation, OpenAPI openAPI) {
        List<String> schemes = new ArrayList<>();

        if (operation.getSecurity() != null) {
            for (SecurityRequirement req : operation.getSecurity()) {
                schemes.addAll(req.keySet());
            }
        } else if (openAPI.getSecurity() != null) {
            for (SecurityRequirement req : openAPI.getSecurity()) {
                schemes.addAll(req.keySet());
            }
        }

        return schemes;
    }
}
