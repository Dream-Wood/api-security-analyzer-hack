package cli;

import model.Severity;
import model.ValidationFinding;

import java.io.PrintWriter;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Formats analysis results for console output.
 */
public final class ResultFormatter {

    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_RED = "\u001B[31m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_BLUE = "\u001B[34m";
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_GRAY = "\u001B[90m";
    private static final String ANSI_BOLD = "\u001B[1m";

    private final PrintWriter out;
    private final boolean useColors;

    public ResultFormatter(PrintWriter out, boolean useColors) {
        this.out = out;
        this.useColors = useColors;
    }

    public ResultFormatter(PrintWriter out) {
        this(out, true);
    }

    /**
     * Formats and prints the complete analysis result.
     */
    public void printResult(SpecAnalyzer.AnalysisResult result, String location) {
        printHeader("API Security Analyzer");
        out.println("Analyzing: " + location);
        out.println();

        if (!result.isSuccessful()) {
            printError(result.getErrorMessage());
            return;
        }

        // Print parsing messages if any
        if (result.hasParsingMessages()) {
            printSection("Parsing Messages");
            for (String message : result.getParsingMessages()) {
                out.println(colorize("  [WARN] ", ANSI_YELLOW) + message);
            }
            out.println();
        }

        // Print validation findings
        List<ValidationFinding> findings = result.getValidationFindings();
        if (findings.isEmpty()) {
            printSuccess("No security or validation issues found!");
            return;
        }

        printSection("Validation Findings");
        printSummary(findings);
        out.println();
        printDetailedFindings(findings);
    }

    private void printHeader(String title) {
        out.println(colorize(ANSI_BOLD + "=".repeat(60), ANSI_BLUE));
        out.println(colorize(ANSI_BOLD + title, ANSI_BLUE));
        out.println(colorize(ANSI_BOLD + "=".repeat(60), ANSI_BLUE));
        out.println();
    }

    private void printSection(String title) {
        out.println(colorize(ANSI_BOLD + title, ANSI_BLUE));
        out.println(colorize("-".repeat(60), ANSI_BLUE));
    }

    private void printError(String message) {
        out.println(colorize("ERROR: ", ANSI_RED) + message);
        out.println();
    }

    private void printSuccess(String message) {
        out.println(colorize("✓ ", ANSI_GREEN) + message);
        out.println();
    }

    private void printSummary(List<ValidationFinding> findings) {
        Map<Severity, Long> countsBySeverity = findings.stream()
            .collect(Collectors.groupingBy(ValidationFinding::getSeverity, Collectors.counting()));

        out.println("Total issues found: " + colorize(String.valueOf(findings.size()), ANSI_BOLD));
        out.println();

        for (Severity severity : Severity.values()) {
            long count = countsBySeverity.getOrDefault(severity, 0L);
            if (count > 0) {
                String severityColor = getSeverityColor(severity);
                String icon = getSeverityIcon(severity);
                out.println("  " + colorize(icon + " " + severity.getDisplayName() + ": " + count, severityColor));
            }
        }
    }

    private void printDetailedFindings(List<ValidationFinding> findings) {
        // Group by severity
        Map<Severity, List<ValidationFinding>> groupedBySeverity = findings.stream()
            .collect(Collectors.groupingBy(ValidationFinding::getSeverity));

        // Print in order: CRITICAL, HIGH, MEDIUM, LOW, INFO
        for (Severity severity : Severity.values()) {
            List<ValidationFinding> severityFindings = groupedBySeverity.get(severity);
            if (severityFindings == null || severityFindings.isEmpty()) {
                continue;
            }

            out.println();
            out.println(colorize(ANSI_BOLD + "["+ severity.getDisplayName().toUpperCase() + "]", getSeverityColor(severity)));
            out.println();

            for (ValidationFinding finding : severityFindings) {
                printFinding(finding);
            }
        }
    }

    private void printFinding(ValidationFinding finding) {
        String severityColor = getSeverityColor(finding.getSeverity());
        String icon = getSeverityIcon(finding.getSeverity());

        out.println(colorize(icon + " " + finding.getType(), severityColor));

        if (finding.getPath() != null || finding.getMethod() != null) {
            out.print("  Location: ");
            if (finding.getMethod() != null) {
                out.print(colorize(finding.getMethod(), ANSI_BOLD) + " ");
            }
            if (finding.getPath() != null) {
                out.print(finding.getPath());
            }
            out.println();
        }

        if (finding.getDetails() != null) {
            out.println("  Details: " + finding.getDetails());
        }

        if (finding.getRecommendation() != null) {
            out.println("  " + colorize("Recommendation:", ANSI_GREEN) + " " + finding.getRecommendation());
        }

        out.println("  " + colorize("ID: " + finding.getId(), ANSI_GRAY));
        out.println();
    }

    private String getSeverityIcon(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "🔴";
            case HIGH -> "🟠";
            case MEDIUM -> "🟡";
            case LOW -> "🔵";
            case INFO -> "ℹ️";
        };
    }

    private String getSeverityColor(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> ANSI_RED;
            case MEDIUM -> ANSI_YELLOW;
            case LOW -> ANSI_BLUE;
            case INFO -> ANSI_GRAY;
        };
    }

    private String colorize(String text, String colorCode) {
        if (!useColors) {
            return text;
        }
        return colorCode + text + ANSI_RESET;
    }
}
