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
        PATH, QUERY, HEADER, COOKIE
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

    @Override
    public String toString() {
        return "ParameterSpec{" +
                "name='" + name + '\'' +
                ", location=" + location +
                ", required=" + required +
                ", type='" + type + '\'' +
                '}';
    }
}
