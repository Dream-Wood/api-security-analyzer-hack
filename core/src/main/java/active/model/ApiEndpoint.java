package active.model;

import model.ParameterSpec;

import java.util.*;

/**
 * Represents an API endpoint to be tested for vulnerabilities.
 */
public final class ApiEndpoint {
    private final String path;
    private final String method;
    private final String operationId;
    private final List<ParameterSpec> parameters;
    private final List<String> securitySchemes;
    private final Map<String, Object> metadata;

    private ApiEndpoint(Builder builder) {
        this.path = Objects.requireNonNull(builder.path, "path cannot be null");
        this.method = Objects.requireNonNull(builder.method, "method cannot be null").toUpperCase();
        this.operationId = builder.operationId;
        this.parameters = builder.parameters != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.parameters))
            : Collections.emptyList();
        this.securitySchemes = builder.securitySchemes != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.securitySchemes))
            : Collections.emptyList();
        this.metadata = builder.metadata != null
            ? Collections.unmodifiableMap(new HashMap<>(builder.metadata))
            : Collections.emptyMap();
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

    public List<ParameterSpec> getParameters() {
        return parameters;
    }

    public List<String> getSecuritySchemes() {
        return securitySchemes;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public boolean requiresAuthentication() {
        return !securitySchemes.isEmpty();
    }

    public List<ParameterSpec> getPathParameters() {
        return parameters.stream()
            .filter(p -> "path".equalsIgnoreCase(p.getIn()))
            .toList();
    }

    public List<ParameterSpec> getQueryParameters() {
        return parameters.stream()
            .filter(p -> "query".equalsIgnoreCase(p.getIn()))
            .toList();
    }

    @Override
    public String toString() {
        return method + " " + path + (operationId != null ? " (" + operationId + ")" : "");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ApiEndpoint that = (ApiEndpoint) o;
        return Objects.equals(path, that.path) && Objects.equals(method, that.method);
    }

    @Override
    public int hashCode() {
        return Objects.hash(path, method);
    }

    public static class Builder {
        private String path;
        private String method;
        private String operationId;
        private List<ParameterSpec> parameters;
        private List<String> securitySchemes;
        private Map<String, Object> metadata;

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

        public Builder parameters(List<ParameterSpec> parameters) {
            this.parameters = parameters;
            return this;
        }

        public Builder securitySchemes(List<String> securitySchemes) {
            this.securitySchemes = securitySchemes;
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }

        public Builder addMetadata(String key, Object value) {
            if (this.metadata == null) {
                this.metadata = new HashMap<>();
            }
            this.metadata.put(key, value);
            return this;
        }

        public ApiEndpoint build() {
            return new ApiEndpoint(this);
        }
    }
}
