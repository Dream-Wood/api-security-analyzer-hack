package report;

/**
 * Factory for creating reporter instances.
 */
public final class ReporterFactory {

    private ReporterFactory() {
        // Utility class
    }

    /**
     * Create a reporter for the specified format.
     *
     * @param format the report format
     * @param useColors whether to use colors (for console format)
     * @return the reporter instance
     */
    public static Reporter createReporter(ReportFormat format, boolean useColors) {
        return switch (format) {
            case CONSOLE -> new ConsoleReporter(useColors);
            case JSON -> new JsonReporter();
            case HTML, TEXT -> throw new UnsupportedOperationException(
                "Format " + format + " is not yet implemented");
        };
    }

    /**
     * Create a reporter for the specified format with default settings.
     *
     * @param format the report format
     * @return the reporter instance
     */
    public static Reporter createReporter(ReportFormat format) {
        return createReporter(format, true);
    }
}
