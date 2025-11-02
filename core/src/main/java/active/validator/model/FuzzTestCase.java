package active.validator.model;

import java.util.*;

/**
 * Represents a fuzzing test case with malformed or edge-case data.
 */
public final class FuzzTestCase {
    private final String name;
    private final String description;
    private final FuzzCategory category;
    private final Map<String, Object> parameters;
    private final Object bodyPayload;
    private final Map<String, String> headers;
    private final ExpectedBehavior expectedBehavior;

    private FuzzTestCase(Builder builder) {
        this.name = Objects.requireNonNull(builder.name, "name cannot be null");
        this.description = builder.description;
        this.category = Objects.requireNonNull(builder.category, "category cannot be null");
        this.parameters = builder.parameters != null
            ? Collections.unmodifiableMap(new HashMap<>(builder.parameters))
            : Collections.emptyMap();
        this.bodyPayload = builder.bodyPayload;
        this.headers = builder.headers != null
            ? Collections.unmodifiableMap(new HashMap<>(builder.headers))
            : Collections.emptyMap();
        this.expectedBehavior = builder.expectedBehavior != null
            ? builder.expectedBehavior
            : ExpectedBehavior.GRACEFUL_ERROR;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public FuzzCategory getCategory() {
        return category;
    }

    public Map<String, Object> getParameters() {
        return parameters;
    }

    public Object getBodyPayload() {
        return bodyPayload;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public ExpectedBehavior getExpectedBehavior() {
        return expectedBehavior;
    }

    @Override
    public String toString() {
        return String.format("FuzzTestCase{name='%s', category=%s}", name, category);
    }

    /**
     * Categories of fuzzing tests.
     */
    public enum FuzzCategory {
        BOUNDARY_VALUE,      // Edge cases (min/max values, empty, null)
        TYPE_CONFUSION,      // Wrong data types
        INJECTION,           // SQL, NoSQL, Command injection attempts
        FORMAT_VIOLATION,    // Invalid formats (email, date, URL, etc.)
        OVERFLOW,            // Very large inputs
        SPECIAL_CHARACTERS,  // Special/Unicode characters
        ENCODING,            // Various encodings (UTF-8, Base64, URL encoding)
        ARRAY_MANIPULATION,  // Empty arrays, single item, many items
        NULL_VALUES,         // Null in various places
        AUTHENTICATION      // Missing/invalid auth tokens
    }

    /**
     * Expected behavior after fuzzing.
     */
    public enum ExpectedBehavior {
        GRACEFUL_ERROR,      // Should return proper error (4xx)
        REJECT_INVALID,      // Should reject with validation error
        NO_CRASH,            // Should not crash (no 5xx)
        CONSISTENT_SCHEMA    // Response schema should remain consistent
    }

    public static class Builder {
        private String name;
        private String description;
        private FuzzCategory category;
        private Map<String, Object> parameters;
        private Object bodyPayload;
        private Map<String, String> headers;
        private ExpectedBehavior expectedBehavior;

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder category(FuzzCategory category) {
            this.category = category;
            return this;
        }

        public Builder parameters(Map<String, Object> parameters) {
            this.parameters = parameters;
            return this;
        }

        public Builder addParameter(String key, Object value) {
            if (this.parameters == null) {
                this.parameters = new HashMap<>();
            }
            this.parameters.put(key, value);
            return this;
        }

        public Builder bodyPayload(Object bodyPayload) {
            this.bodyPayload = bodyPayload;
            return this;
        }

        public Builder headers(Map<String, String> headers) {
            this.headers = headers;
            return this;
        }

        public Builder addHeader(String key, String value) {
            if (this.headers == null) {
                this.headers = new HashMap<>();
            }
            this.headers.put(key, value);
            return this;
        }

        public Builder expectedBehavior(ExpectedBehavior expectedBehavior) {
            this.expectedBehavior = expectedBehavior;
            return this;
        }

        public FuzzTestCase build() {
            return new FuzzTestCase(this);
        }
    }
}
