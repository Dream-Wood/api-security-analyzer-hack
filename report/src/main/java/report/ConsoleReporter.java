package report;

import active.ActiveAnalysisEngine;
import active.model.VulnerabilityReport;
import active.validator.ContractValidationEngine;
import active.validator.model.Divergence;
import active.validator.model.ValidationResult;
import model.Severity;
import model.ValidationFinding;

import java.io.IOException;
import java.io.PrintWriter;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Console-based reporter with colored output.
 */
public final class ConsoleReporter implements Reporter {

    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_RED = "\u001B[31m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_BLUE = "\u001B[34m";
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_GRAY = "\u001B[90m";
    private static final String ANSI_BOLD = "\u001B[1m";
    private static final String ANSI_CYAN = "\u001B[36m";

    private final boolean useColors;

    public ConsoleReporter(boolean useColors) {
        this.useColors = useColors;
    }

    public ConsoleReporter() {
        this(true);
    }

    @Override
    public void generate(AnalysisReport report, PrintWriter writer) throws IOException {
        printHeader(writer, "API Security Analyzer");
        writer.println("Analyzing: " + report.getSpecLocation());
        writer.println("Mode: " + colorize(report.getMode().toString(), ANSI_CYAN));

        Duration duration = Duration.between(report.getStartTime(), report.getEndTime());
        writer.println("Duration: " + formatDuration(duration));
        writer.println();

        // Static analysis results
        if (report.hasStaticResults()) {
            printStaticResults(writer, report.getStaticResult());
        }

        // Active analysis results
        if (report.hasActiveResults()) {
            printActiveResults(writer, report.getActiveResult());
        }

        // Contract validation results
        if (report.hasContractResults()) {
            printContractResults(writer, report.getContractResult());
        }

        // Summary
        printSummary(writer, report);
    }

    private void printStaticResults(PrintWriter writer, AnalysisReport.StaticAnalysisResult result) {
        printSection(writer, "Static Analysis Results");

        if (result.hasError()) {
            printError(writer, result.getErrorMessage());
            return;
        }

        // Parsing messages
        if (!result.getParsingMessages().isEmpty()) {
            writer.println(colorize("Parsing Messages:", ANSI_BOLD));
            for (String message : result.getParsingMessages()) {
                writer.println(colorize("  [WARN] ", ANSI_YELLOW) + message);
            }
            writer.println();
        }

        // Validation findings
        List<ValidationFinding> findings = result.getFindings();
        if (findings.isEmpty()) {
            printSuccess(writer, "No static analysis issues found!");
        } else {
            writer.println("Found " + colorize(String.valueOf(findings.size()), ANSI_BOLD) + " issues");
            writer.println();
            printFindingsSummary(writer, findings);
            writer.println();
            printDetailedFindings(writer, findings);
        }
    }

    private void printActiveResults(PrintWriter writer, AnalysisReport.ActiveAnalysisResult result) {
        printSection(writer, "Active Analysis Results");

        if (result.hasError()) {
            printError(writer, result.getErrorMessage());
            return;
        }

        ActiveAnalysisEngine.AnalysisReport activeReport = result.getReport();

        writer.println("Endpoints scanned: " + activeReport.getEndpointCount());
        writer.println("Vulnerable endpoints: " + colorize(
            String.valueOf(activeReport.getVulnerableEndpointCount()), ANSI_RED));
        writer.println("Total vulnerabilities: " + colorize(
            String.valueOf(activeReport.getTotalVulnerabilityCount()), ANSI_BOLD));
        writer.println();

        if (activeReport.getTotalVulnerabilityCount() == 0) {
            printSuccess(writer, "No vulnerabilities found!");
        } else {
            printVulnerabilitySummary(writer, activeReport);
            writer.println();
            printDetailedVulnerabilities(writer, activeReport);
        }
    }

    private void printContractResults(PrintWriter writer, AnalysisReport.ContractAnalysisResult result) {
        printSection(writer, "Contract Validation Results");

        if (result.hasError()) {
            printError(writer, result.getErrorMessage());
            return;
        }

        ContractValidationEngine.ContractValidationReport contractReport = result.getReport();

        writer.println("Endpoints validated: " + contractReport.getTotalEndpoints());
        writer.println("Total divergences: " + colorize(
            String.valueOf(contractReport.getTotalDivergences()), ANSI_BOLD));
        writer.println("Critical divergences: " + colorize(
            String.valueOf(contractReport.getCriticalDivergences()), ANSI_RED));
        writer.println("High divergences: " + colorize(
            String.valueOf(contractReport.getHighDivergences()), ANSI_YELLOW));
        writer.println("Fuzzing: " + (contractReport.isFuzzingEnabled() ? "Enabled" : "Disabled"));
        writer.println();

        if (contractReport.getTotalDivergences() == 0) {
            printSuccess(writer, "No contract divergences found!");
        } else {
            printDivergencesSummary(writer, contractReport);
            writer.println();
            printDetailedDivergences(writer, contractReport);
        }
    }

    private void printDivergencesSummary(PrintWriter writer, ContractValidationEngine.ContractValidationReport report) {
        Map<Divergence.Severity, List<Divergence>> bySeverity = report.getDivergencesBySeverity();

        writer.println(colorize("By Severity:", ANSI_BOLD));
        for (Divergence.Severity severity : Divergence.Severity.values()) {
            List<Divergence> divergences = bySeverity.get(severity);
            if (divergences != null && !divergences.isEmpty()) {
                String severityColor = getDivergenceSeverityColor(severity);
                String icon = getDivergenceSeverityIcon(severity);
                writer.println("  " + colorize(icon + " " + severity.name() + ": " + divergences.size(), severityColor));
            }
        }
    }

    private void printDetailedDivergences(PrintWriter writer, ContractValidationEngine.ContractValidationReport report) {
        Map<Divergence.Severity, List<Divergence>> bySeverity = report.getDivergencesBySeverity();

        for (Divergence.Severity severity : Divergence.Severity.values()) {
            List<Divergence> divergences = bySeverity.get(severity);
            if (divergences == null || divergences.isEmpty()) {
                continue;
            }

            writer.println();
            writer.println(colorize(ANSI_BOLD + "[" + severity.name() + "]",
                getDivergenceSeverityColor(severity)));
            writer.println();

            for (Divergence divergence : divergences) {
                printDivergence(writer, divergence);
            }
        }
    }

    private void printDivergence(PrintWriter writer, Divergence divergence) {
        String severityColor = getDivergenceSeverityColor(divergence.getSeverity());
        String icon = getDivergenceSeverityIcon(divergence.getSeverity());

        writer.println(colorize(icon + " " + divergence.getType().name(), severityColor));

        if (divergence.getPath() != null) {
            writer.print("  Path: " + colorize(divergence.getPath(), ANSI_BOLD));
            if (divergence.getField() != null) {
                writer.print(" → " + divergence.getField());
            }
            writer.println();
        }

        writer.println("  Message: " + divergence.getMessage());

        if (divergence.getExpectedValue() != null) {
            writer.println("  Expected: " + divergence.getExpectedValue());
        }

        if (divergence.getActualValue() != null) {
            writer.println("  Actual: " + divergence.getActualValue());
        }

        writer.println();
    }

    private String getDivergenceSeverityIcon(Divergence.Severity severity) {
        return switch (severity) {
            case CRITICAL -> "🔴";
            case HIGH -> "🟠";
            case MEDIUM -> "🟡";
            case LOW -> "🔵";
        };
    }

    private String getDivergenceSeverityColor(Divergence.Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> ANSI_RED;
            case MEDIUM -> ANSI_YELLOW;
            case LOW -> ANSI_BLUE;
        };
    }

    private void printFindingsSummary(PrintWriter writer, List<ValidationFinding> findings) {
        Map<Severity, Long> countsBySeverity = findings.stream()
            .collect(Collectors.groupingBy(ValidationFinding::getSeverity, Collectors.counting()));

        writer.println(colorize("By Severity:", ANSI_BOLD));
        for (Severity severity : Severity.values()) {
            long count = countsBySeverity.getOrDefault(severity, 0L);
            if (count > 0) {
                String severityColor = getSeverityColor(severity);
                String icon = getSeverityIcon(severity);
                writer.println("  " + colorize(icon + " " + severity.getDisplayName() + ": " + count, severityColor));
            }
        }
    }

    private void printDetailedFindings(PrintWriter writer, List<ValidationFinding> findings) {
        Map<Severity, List<ValidationFinding>> groupedBySeverity = findings.stream()
            .collect(Collectors.groupingBy(ValidationFinding::getSeverity));

        for (Severity severity : Severity.values()) {
            List<ValidationFinding> severityFindings = groupedBySeverity.get(severity);
            if (severityFindings == null || severityFindings.isEmpty()) {
                continue;
            }

            writer.println();
            writer.println(colorize(ANSI_BOLD + "[" + severity.getDisplayName().toUpperCase() + "]",
                getSeverityColor(severity)));
            writer.println();

            for (ValidationFinding finding : severityFindings) {
                printFinding(writer, finding);
            }
        }
    }

    private void printFinding(PrintWriter writer, ValidationFinding finding) {
        String severityColor = getSeverityColor(finding.getSeverity());
        String icon = getSeverityIcon(finding.getSeverity());

        writer.println(colorize(icon + " " + finding.getType(), severityColor));

        if (finding.getPath() != null || finding.getMethod() != null) {
            writer.print("  Location: ");
            if (finding.getMethod() != null) {
                writer.print(colorize(finding.getMethod(), ANSI_BOLD) + " ");
            }
            if (finding.getPath() != null) {
                writer.print(finding.getPath());
            }
            writer.println();
        }

        if (finding.getDetails() != null) {
            writer.println("  Details: " + finding.getDetails());
        }

        if (finding.getRecommendation() != null) {
            writer.println("  " + colorize("Recommendation:", ANSI_GREEN) + " " + finding.getRecommendation());
        }

        writer.println("  " + colorize("ID: " + finding.getId(), ANSI_GRAY));
        writer.println();
    }

    private void printVulnerabilitySummary(PrintWriter writer, ActiveAnalysisEngine.AnalysisReport report) {
        writer.println(colorize("By Severity:", ANSI_BOLD));
        report.getVulnerabilityCountBySeverity().forEach((severity, count) -> {
            String icon = getSeverityIcon(severity);
            String color = getSeverityColor(severity);
            writer.println("  " + colorize(icon + " " + severity.getDisplayName() + ": " + count, color));
        });

        writer.println();
        writer.println(colorize("By Type:", ANSI_BOLD));
        report.getVulnerabilityCountByType().forEach((type, count) -> {
            writer.println("  • " + type.getDisplayName() + ": " + count);
        });
    }

    private void printDetailedVulnerabilities(PrintWriter writer, ActiveAnalysisEngine.AnalysisReport report) {
        writer.println();
        writer.println(colorize("Detailed Vulnerabilities:", ANSI_BOLD));
        writer.println();

        for (ActiveAnalysisEngine.EndpointAnalysisResult endpointResult : report.getEndpointResults()) {
            if (endpointResult.getVulnerabilityCount() == 0) {
                continue;
            }

            writer.println(colorize("Endpoint: " + endpointResult.endpoint(), ANSI_CYAN));
            writer.println();

            for (VulnerabilityReport vuln : endpointResult.getAllVulnerabilities()) {
                printVulnerability(writer, vuln);
            }
        }
    }

    private void printVulnerability(PrintWriter writer, VulnerabilityReport vuln) {
        String icon = getSeverityIcon(vuln.getSeverity());
        String color = getSeverityColor(vuln.getSeverity());

        writer.println(colorize(icon + " " + vuln.getTitle(), color));
        writer.println("  Type: " + vuln.getType().getDisplayName() + " (" + vuln.getType().getCategory() + ")");
        writer.println("  Severity: " + colorize(vuln.getSeverity().getDisplayName(), color));

        if (vuln.getDescription() != null) {
            writer.println("  Description: " + vuln.getDescription());
        }

        if (vuln.getReproductionSteps() != null) {
            writer.println("  " + colorize("Reproduction:", ANSI_BOLD));
            writer.println("    " + vuln.getReproductionSteps());
        }

        if (!vuln.getRecommendations().isEmpty()) {
            writer.println("  " + colorize("Recommendations:", ANSI_GREEN));
            for (String rec : vuln.getRecommendations()) {
                writer.println("    • " + rec);
            }
        }

        writer.println("  " + colorize("ID: " + vuln.getId(), ANSI_GRAY));
        writer.println();
    }

    private void printSummary(PrintWriter writer, AnalysisReport report) {
        printSection(writer, "Summary");

        int totalIssues = report.getTotalIssueCount();

        if (totalIssues == 0) {
            printSuccess(writer, "Analysis completed successfully with no issues found!");
        } else {
            writer.println("Total issues found: " + colorize(String.valueOf(totalIssues), ANSI_RED));

            if (report.hasStaticResults() && !report.getStaticResult().hasError()) {
                writer.println("  Static issues: " + report.getStaticResult().getFindings().size());
            }

            if (report.hasActiveResults() && !report.getActiveResult().hasError()) {
                writer.println("  Active vulnerabilities: " +
                    report.getActiveResult().getReport().getTotalVulnerabilityCount());
            }

            if (report.hasContractResults() && !report.getContractResult().hasError()) {
                writer.println("  Contract divergences: " +
                    report.getContractResult().getReport().getTotalDivergences());
            }
        }

        writer.println();
    }

    private void printHeader(PrintWriter writer, String title) {
        writer.println(colorize(ANSI_BOLD + "=".repeat(60), ANSI_BLUE));
        writer.println(colorize(ANSI_BOLD + title, ANSI_BLUE));
        writer.println(colorize(ANSI_BOLD + "=".repeat(60), ANSI_BLUE));
        writer.println();
    }

    private void printSection(PrintWriter writer, String title) {
        writer.println();
        writer.println(colorize(ANSI_BOLD + title, ANSI_BLUE));
        writer.println(colorize("-".repeat(60), ANSI_BLUE));
    }

    private void printError(PrintWriter writer, String message) {
        writer.println(colorize("ERROR: ", ANSI_RED) + message);
        writer.println();
    }

    private void printSuccess(PrintWriter writer, String message) {
        writer.println(colorize("✓ ", ANSI_GREEN) + message);
        writer.println();
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

    private String formatDuration(Duration duration) {
        long seconds = duration.getSeconds();
        if (seconds < 60) {
            return seconds + "s";
        }
        long minutes = seconds / 60;
        long remainingSeconds = seconds % 60;
        return minutes + "m " + remainingSeconds + "s";
    }

    @Override
    public ReportFormat getFormat() {
        return ReportFormat.CONSOLE;
    }
}
