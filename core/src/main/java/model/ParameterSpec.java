package model;

import java.util.Objects;

/**
 * Represents a parameter in an API operation (path, query, header, cookie).
 */
public final class ParameterSpec {
    private final String name;
    private final ParameterLocation location;
    private final boolean required;
    private final String type;
    private final String description;
    private final Object defaultValue;

    public enum ParameterLocation {
        PATH("path"),
        QUERY("query"),
        HEADER("header"),
        COOKIE("cookie");

        private final String value;

        ParameterLocation(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        public static ParameterLocation fromString(String value) {
            for (ParameterLocation loc : values()) {
                if (loc.value.equalsIgnoreCase(value)) {
                    return loc;
                }
            }
            throw new IllegalArgumentException("Unknown parameter location: " + value);
        }
    }

    public ParameterSpec(String name, ParameterLocation location, boolean required,
                        String type, String description, Object defaultValue) {
        this.name = Objects.requireNonNull(name, "Parameter name cannot be null");
        this.location = Objects.requireNonNull(location, "Parameter location cannot be null");
        this.required = required;
        this.type = type;
        this.description = description;
        this.defaultValue = defaultValue;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getName() {
        return name;
    }

    public ParameterLocation getLocation() {
        return location;
    }

    public boolean isRequired() {
        return required;
    }

    public String getType() {
        return type;
    }

    public String getDescription() {
        return description;
    }

    public Object getDefaultValue() {
        return defaultValue;
    }

    /**
     * Get the location as a string (for compatibility).
     * @return "path", "query", "header", or "cookie"
     */
    public String getIn() {
        return location.getValue();
    }

    @Override
    public String toString() {
        return "ParameterSpec{" +
                "name='" + name + '\'' +
                ", location=" + location +
                ", required=" + required +
                ", type='" + type + '\'' +
                '}';
    }

    public static class Builder {
        private String name;
        private ParameterLocation location;
        private boolean required;
        private String type;
        private String description;
        private Object defaultValue;

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder location(ParameterLocation location) {
            this.location = location;
            return this;
        }

        public Builder in(String in) {
            this.location = ParameterLocation.fromString(in);
            return this;
        }

        public Builder required(boolean required) {
            this.required = required;
            return this;
        }

        public Builder type(String type) {
            this.type = type;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder defaultValue(Object defaultValue) {
            this.defaultValue = defaultValue;
            return this;
        }

        public ParameterSpec build() {
            return new ParameterSpec(name, location, required, type, description, defaultValue);
        }
    }
}
