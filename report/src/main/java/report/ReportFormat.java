package report;

/**
 * Supported report output formats.
 */
public enum ReportFormat {
    CONSOLE("Console output with colors"),
    JSON("JSON format"),
    HTML("HTML report"),
    TEXT("Plain text");

    private final String description;

    ReportFormat(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
