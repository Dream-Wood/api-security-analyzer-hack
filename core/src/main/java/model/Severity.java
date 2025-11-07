package model;

/**
 * Уровни критичности для результатов валидации.
 * Определяет приоритет и диапазон оценок для каждого уровня критичности.
 */
public enum Severity {
    CRITICAL("Critical", 4, 9.0, 10.0),
    HIGH("High", 3, 7.0, 8.9),
    MEDIUM("Medium", 2, 4.0, 6.9),
    LOW("Low", 1, 0.1, 3.9),
    INFO("Info", 0, 0.0, 0.0);

    private final String displayName;
    private final int priority;
    private final double minScore;
    private final double maxScore;

    Severity(String displayName, int priority, double minScore, double maxScore) {
        this.displayName = displayName;
        this.priority = priority;
        this.minScore = minScore;
        this.maxScore = maxScore;
    }

    public String getDisplayName() {
        return displayName;
    }

    public int getPriority() {
        return priority;
    }

    public double getMinScore() {
        return minScore;
    }

    public double getMaxScore() {
        return maxScore;
    }

    public static Severity fromScore(double score) {
        for (Severity severity : values()) {
            if (score >= severity.minScore && score <= severity.maxScore) {
                return severity;
            }
        }
        return INFO;
    }

    public boolean isCriticalOrHigh() {
        return this == CRITICAL || this == HIGH;
    }
}
