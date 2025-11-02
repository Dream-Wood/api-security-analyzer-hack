package active.validator.model;

import java.util.*;

/**
 * Represents a divergence between API specification and actual behavior.
 */
public final class Divergence {
    private final DivergenceType type;
    private final String path;
    private final String field;
    private final Object expectedValue;
    private final Object actualValue;
    private final String message;
    private final Severity severity;
    private final Map<String, Object> metadata;

    private Divergence(Builder builder) {
        this.type = Objects.requireNonNull(builder.type, "type cannot be null");
        this.path = builder.path;
        this.field = builder.field;
        this.expectedValue = builder.expectedValue;
        this.actualValue = builder.actualValue;
        this.message = Objects.requireNonNull(builder.message, "message cannot be null");
        this.severity = builder.severity != null ? builder.severity : Severity.MEDIUM;
        this.metadata = builder.metadata != null
            ? Collections.unmodifiableMap(new HashMap<>(builder.metadata))
            : Collections.emptyMap();
    }

    public static Builder builder() {
        return new Builder();
    }

    public DivergenceType getType() {
        return type;
    }

    public String getPath() {
        return path;
    }

    public String getField() {
        return field;
    }

    public Object getExpectedValue() {
        return expectedValue;
    }

    public Object getActualValue() {
        return actualValue;
    }

    public String getMessage() {
        return message;
    }

    public Severity getSeverity() {
        return severity;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    @Override
    public String toString() {
        return String.format("Divergence{type=%s, severity=%s, path='%s', field='%s', message='%s'}",
            type, severity, path, field, message);
    }

    public enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    public static class Builder {
        private DivergenceType type;
        private String path;
        private String field;
        private Object expectedValue;
        private Object actualValue;
        private String message;
        private Severity severity;
        private Map<String, Object> metadata;

        public Builder type(DivergenceType type) {
            this.type = type;
            return this;
        }

        public Builder path(String path) {
            this.path = path;
            return this;
        }

        public Builder field(String field) {
            this.field = field;
            return this;
        }

        public Builder expectedValue(Object expectedValue) {
            this.expectedValue = expectedValue;
            return this;
        }

        public Builder actualValue(Object actualValue) {
            this.actualValue = actualValue;
            return this;
        }

        public Builder message(String message) {
            this.message = message;
            return this;
        }

        public Builder severity(Severity severity) {
            this.severity = severity;
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

        public Divergence build() {
            return new Divergence(this);
        }
    }
}
