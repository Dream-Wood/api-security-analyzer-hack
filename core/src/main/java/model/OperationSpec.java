package model;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;

/**
 * Enhanced representation of an API operation with comprehensive metadata.
 */
public final class OperationSpec {
    private final String path;
    private final String method;
    private final String operationId;
    private final String summary;
    private final String description;
    private final Map<String, JsonNode> responsesByCode;
    private final Optional<JsonNode> requestBodySchema;
    private final List<ParameterSpec> parameters;
    private final List<String> securitySchemes;
    private final List<String> tags;
    private final boolean deprecated;

    private OperationSpec(Builder builder) {
        this.path = Objects.requireNonNull(builder.path, "path cannot be null");
        this.method = Objects.requireNonNull(builder.method, "method cannot be null");
        this.operationId = builder.operationId;
        this.summary = builder.summary;
        this.description = builder.description;
        this.responsesByCode = builder.responsesByCode != null
            ? Collections.unmodifiableMap(new LinkedHashMap<>(builder.responsesByCode))
            : Collections.emptyMap();
        this.requestBodySchema = builder.requestBodySchema != null
            ? builder.requestBodySchema
            : Optional.empty();
        this.parameters = builder.parameters != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.parameters))
            : Collections.emptyList();
        this.securitySchemes = builder.securitySchemes != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.securitySchemes))
            : Collections.emptyList();
        this.tags = builder.tags != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.tags))
            : Collections.emptyList();
        this.deprecated = builder.deprecated;
    }

    // TODO: Legacy constructor for backward compatibility
    public OperationSpec(String path, String method, String operationId,
                         Map<String, JsonNode> responsesByCode,
                         Optional<JsonNode> requestBodySchema) {
        this.path = Objects.requireNonNull(path);
        this.method = Objects.requireNonNull(method);
        this.operationId = operationId;
        this.summary = null;
        this.description = null;
        this.responsesByCode = responsesByCode == null ? Collections.emptyMap() : Map.copyOf(responsesByCode);
        this.requestBodySchema = requestBodySchema == null ? Optional.empty() : requestBodySchema;
        this.parameters = Collections.emptyList();
        this.securitySchemes = Collections.emptyList();
        this.tags = Collections.emptyList();
        this.deprecated = false;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getPath() {
        return path;
    }

    public String getMethod() {
        return method;
    }

    public String getOperationId() {
        return operationId;
    }

    public String getSummary() {
        return summary;
    }

    public String getDescription() {
        return description;
    }

    public Map<String, JsonNode> getResponsesByCode() {
        return responsesByCode;
    }

    public Optional<JsonNode> getRequestBodySchema() {
        return requestBodySchema;
    }

    public List<ParameterSpec> getParameters() {
        return parameters;
    }

    public List<String> getSecuritySchemes() {
        return securitySchemes;
    }

    public List<String> getTags() {
        return tags;
    }

    public boolean isDeprecated() {
        return deprecated;
    }

    public boolean hasSuccessResponse() {
        return responsesByCode.keySet().stream()
            .anyMatch(code -> code.matches("^2\\d\\d$"));
    }

    public boolean hasErrorHandling() {
        return responsesByCode.keySet().stream()
            .anyMatch(code -> code.matches("^[45]\\d\\d$"));
    }

    public boolean requiresAuthentication() {
        return !securitySchemes.isEmpty();
    }

    @Override
    public String toString() {
        return "OperationSpec{" +
                "method='" + method + '\'' +
                ", path='" + path + '\'' +
                ", operationId='" + operationId + '\'' +
                ", deprecated=" + deprecated +
                ", responses=" + responsesByCode.keySet() +
                '}';
    }

    public static class Builder {
        private String path;
        private String method;
        private String operationId;
        private String summary;
        private String description;
        private Map<String, JsonNode> responsesByCode;
        private Optional<JsonNode> requestBodySchema;
        private List<ParameterSpec> parameters;
        private List<String> securitySchemes;
        private List<String> tags;
        private boolean deprecated;

        public Builder path(String path) {
            this.path = path;
            return this;
        }

        public Builder method(String method) {
            this.method = method;
            return this;
        }

        public Builder operationId(String operationId) {
            this.operationId = operationId;
            return this;
        }

        public Builder summary(String summary) {
            this.summary = summary;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder responsesByCode(Map<String, JsonNode> responsesByCode) {
            this.responsesByCode = responsesByCode;
            return this;
        }

        public Builder requestBodySchema(Optional<JsonNode> requestBodySchema) {
            this.requestBodySchema = requestBodySchema;
            return this;
        }

        public Builder parameters(List<ParameterSpec> parameters) {
            this.parameters = parameters;
            return this;
        }

        public Builder securitySchemes(List<String> securitySchemes) {
            this.securitySchemes = securitySchemes;
            return this;
        }

        public Builder tags(List<String> tags) {
            this.tags = tags;
            return this;
        }

        public Builder deprecated(boolean deprecated) {
            this.deprecated = deprecated;
            return this;
        }

        public OperationSpec build() {
            return new OperationSpec(this);
        }
    }
}
