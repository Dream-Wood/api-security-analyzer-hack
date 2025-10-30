package model;

import java.util.*;

/**
 * Enhanced ValidationFinding with additional context and categorization.
 */
public final class ValidationFinding {
    private final String id;
    private final Severity severity;
    private final FindingCategory category;
    private final String type;
    private final String path;
    private final String method;
    private final String details;
    private final String recommendation;
    private final Map<String, Object> metadata;

    public enum FindingCategory {
        SECURITY("Security"),
        COMPLIANCE("Compliance"),
        CONTRACT("Contract Validation"),
        PERFORMANCE("Performance"),
        DOCUMENTATION("Documentation"),
        BEST_PRACTICE("Best Practice");

        private final String displayName;

        FindingCategory(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    // TODO: Legacy constructor for backward compatibility
    public ValidationFinding(Severity severity, String type, String path,
                           String method, String details, String recommendation) {
        this(severity, FindingCategory.CONTRACT, type, path, method, details, recommendation, null);
    }

    public ValidationFinding(Severity severity, FindingCategory category, String type,
                           String path, String method, String details,
                           String recommendation, Map<String, Object> metadata) {
        this.id = UUID.randomUUID().toString();
        this.severity = Objects.requireNonNull(severity, "Severity cannot be null");
        this.category = category != null ? category : FindingCategory.CONTRACT;
        this.type = Objects.requireNonNull(type, "Type cannot be null");
        this.path = path;
        this.method = method;
        this.details = details;
        this.recommendation = recommendation;
        this.metadata = metadata != null ? Collections.unmodifiableMap(new HashMap<>(metadata)) : Collections.emptyMap();
    }

    public String getId() {
        return id;
    }

    public Severity getSeverity() {
        return severity;
    }

    public FindingCategory getCategory() {
        return category;
    }

    public String getType() {
        return type;
    }

    public String getPath() {
        return path;
    }

    public String getMethod() {
        return method;
    }

    public String getDetails() {
        return details;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    @Override
    public String toString() {
        return "ValidationFinding{" +
                "id='" + id + '\'' +
                ", severity=" + severity +
                ", category=" + category +
                ", type='" + type + '\'' +
                ", path='" + path + '\'' +
                ", method='" + method + '\'' +
                '}';
    }
}
