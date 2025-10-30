package util;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Utility methods for validation logic.
 */
public final class ValidationUtils {

    private ValidationUtils() {
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Checks if a string matches HTTP 2xx status code pattern.
     */
    public static boolean is2xxStatusCode(String code) {
        return code != null && code.matches("^2\\d\\d$");
    }

    /**
     * Checks if a string matches HTTP 4xx or 5xx status code pattern.
     */
    public static boolean isErrorStatusCode(String code) {
        return code != null && code.matches("^[45]\\d\\d$");
    }

    /**
     * Checks if a JsonNode schema appears to be well-defined.
     */
    public static boolean hasWellDefinedSchema(JsonNode schema) {
        if (schema == null) {
            return false;
        }
        String schemaText = schema.toString();
        return schemaText.contains("\"type\"") || schemaText.contains("\"properties\"");
    }

    /**
     * Checks if a JsonNode schema is an array type.
     */
    public static boolean isArraySchema(JsonNode schema) {
        if (schema == null) {
            return false;
        }
        return schema.toString().contains("\"type\":\"array\"");
    }

    /**
     * Checks if an array schema has items definition.
     */
    public static boolean hasItemsDefinition(JsonNode schema) {
        if (schema == null) {
            return false;
        }
        return schema.toString().contains("\"items\"");
    }

    /**
     * Truncates a string to a maximum length.
     */
    public static String truncate(String str, int maxLength) {
        if (str == null) {
            return "";
        }
        if (str.length() <= maxLength) {
            return str;
        }
        return str.substring(0, maxLength) + "...";
    }

    /**
     * Checks if a path contains path parameters.
     */
    public static boolean hasPathParameters(String path) {
        return path != null && path.contains("{") && path.contains("}");
    }

    /**
     * Extracts path parameter names from a path string.
     */
    public static java.util.List<String> extractPathParameterNames(String path) {
        java.util.List<String> params = new java.util.ArrayList<>();
        if (path == null) {
            return params;
        }

        int start = path.indexOf('{');
        while (start != -1) {
            int end = path.indexOf('}', start);
            if (end != -1) {
                params.add(path.substring(start + 1, end));
                start = path.indexOf('{', end);
            } else {
                break;
            }
        }
        return params;
    }
}
