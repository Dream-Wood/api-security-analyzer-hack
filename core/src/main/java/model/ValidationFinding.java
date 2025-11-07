package model;

import java.util.*;

/**
 * Расширенный класс для представления результата валидации с дополнительным контекстом и категоризацией.
 *
 * <p>Представляет обнаруженные проблемы при валидации спецификации API:
 * <ul>
 *   <li>Уровень критичности (severity)</li>
 *   <li>Категория проблемы (security, compliance, contract и т.д.)</li>
 *   <li>Детальное описание и рекомендации</li>
 *   <li>Контекст (путь, метод, дополнительные метаданные)</li>
 * </ul>
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

    /**
     * Категории проблем валидации.
     */
    public enum FindingCategory {
        /** Проблемы безопасности */
        SECURITY("Security"),

        /** Проблемы соответствия стандартам */
        COMPLIANCE("Compliance"),

        /** Проблемы валидации контрактов */
        CONTRACT("Contract Validation"),

        /** Проблемы производительности */
        PERFORMANCE("Performance"),

        /** Проблемы документации */
        DOCUMENTATION("Documentation"),

        /** Нарушения лучших практик */
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

    /**
     * Строитель для ValidationFinding, следующий лучшим практикам.
     * Позволяет гибко создавать объекты ValidationFinding с различными параметрами.
     */
    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private Severity severity;
        private FindingCategory category = FindingCategory.CONTRACT;
        private String type;
        private String path;
        private String method;
        private String details;
        private String recommendation;
        private Map<String, Object> metadata;

        private Builder() {
        }

        public Builder severity(Severity severity) {
            this.severity = severity;
            return this;
        }

        public Builder category(FindingCategory category) {
            this.category = category;
            return this;
        }

        public Builder type(String type) {
            this.type = type;
            return this;
        }

        public Builder path(String path) {
            this.path = path;
            return this;
        }

        public Builder method(String method) {
            this.method = method;
            return this;
        }

        public Builder details(String details) {
            this.details = details;
            return this;
        }

        public Builder recommendation(String recommendation) {
            this.recommendation = recommendation;
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }

        public ValidationFinding build() {
            return new ValidationFinding(severity, category, type, path, method, details, recommendation, metadata);
        }
    }
}
