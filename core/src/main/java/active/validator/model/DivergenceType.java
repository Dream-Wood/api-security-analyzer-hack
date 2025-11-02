package active.validator.model;

/**
 * Types of divergences between API specification and actual behavior.
 */
public enum DivergenceType {
    /**
     * A required field defined in the specification is missing from the response.
     */
    MISSING_REQUIRED_FIELD,

    /**
     * An unexpected field is present in the response but not defined in the specification.
     */
    UNEXPECTED_FIELD,

    /**
     * The data type of a field doesn't match the specification.
     */
    TYPE_MISMATCH,

    /**
     * The response structure doesn't conform to the schema.
     */
    SCHEMA_VIOLATION,

    /**
     * An endpoint exists but is not documented in the specification.
     */
    UNDOCUMENTED_ENDPOINT,

    /**
     * The status code received doesn't match any defined in the specification.
     */
    UNEXPECTED_STATUS_CODE,

    /**
     * Response content type doesn't match the specification.
     */
    CONTENT_TYPE_MISMATCH,

    /**
     * Array items don't conform to the specified items schema.
     */
    ARRAY_ITEMS_MISMATCH,

    /**
     * Enum value not defined in the specification.
     */
    INVALID_ENUM_VALUE,

    /**
     * Required property defined in the specification is null in response.
     */
    NULL_REQUIRED_FIELD,

    /**
     * Additional properties exist when 'additionalProperties: false'.
     */
    ADDITIONAL_PROPERTIES_FORBIDDEN
}
