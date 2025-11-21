package model;

/**
 * Enum representing the type of API specification.
 */
public enum SpecificationType {
    /**
     * OpenAPI (Swagger) specification for REST APIs.
     */
    OPENAPI("OpenAPI", "openapi", true),

    /**
     * AsyncAPI specification for event-driven APIs.
     */
    ASYNCAPI("AsyncAPI", "asyncapi", true);

    private final String displayName;
    private final String schemaField;
    private final boolean supportsActiveAnalysis;

    SpecificationType(String displayName, String schemaField, boolean supportsActiveAnalysis) {
        this.displayName = displayName;
        this.schemaField = schemaField;
        this.supportsActiveAnalysis = supportsActiveAnalysis;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getSchemaField() {
        return schemaField;
    }

    /**
     * Returns whether this specification type supports active (runtime) analysis.
     *
     * @return true if active analysis is supported, false otherwise
     */
    public boolean supportsActiveAnalysis() {
        return supportsActiveAnalysis;
    }

    /**
     * Returns whether this specification type only supports static analysis.
     *
     * @return true if only static analysis is supported
     */
    public boolean isStaticOnly() {
        return !supportsActiveAnalysis;
    }
}
