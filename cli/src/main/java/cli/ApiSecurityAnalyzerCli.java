package cli;

import active.http.HttpClient;
import report.AnalysisReport;
import report.ReportFormat;
import report.Reporter;
import report.ReporterFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.concurrent.Callable;

/**
 * Main CLI entry point for the API Security Analyzer.
 * Uses picocli for command-line argument parsing.
 */
@Command(
    name = "api-security-analyzer",
    description = "Analyze OpenAPI specifications for security vulnerabilities and compliance issues",
    mixinStandardHelpOptions = true,
    version = "1.0-SNAPSHOT"
)
public class ApiSecurityAnalyzerCli implements Callable<Integer> {

    @Parameters(
        index = "0",
        description = "Path to OpenAPI specification file (YAML/JSON) or URL"
    )
    private String specLocation;

    @Option(
        names = {"-m", "--mode"},
        description = "Analysis mode: static, active, both, contract (default: static)",
        defaultValue = "static"
    )
    private String mode;

    @Option(
        names = {"-u", "--base-url"},
        description = "Base URL for active analysis (overrides servers from spec)"
    )
    private String baseUrl;

    @Option(
        names = {"-a", "--auth-header"},
        description = "Authentication header for active analysis (format: 'Header: Value')"
    )
    private String authHeader;

    @Option(
        names = {"-c", "--crypto-protocol"},
        description = "Cryptographic protocol: standard, gost (default: standard)"
    )
    private String cryptoProtocol;

    @Option(
        names = {"--no-verify-ssl"},
        description = "Disable SSL certificate verification (for testing only!)"
    )
    private boolean noVerifySsl;

    @Option(
        names = {"-f", "--format"},
        description = "Output format: console, json (default: console)"
    )
    private String format;

    @Option(
        names = {"-nc", "--no-color"},
        description = "Disable colored output"
    )
    private boolean noColor;

    @Option(
        names = {"-v", "--verbose"},
        description = "Enable verbose output"
    )
    private boolean verbose;

    @Option(
        names = {"--no-fuzzing"},
        description = "Disable fuzzing in contract validation (faster)"
    )
    private boolean noFuzzing;

    @Option(
        names = {"-o", "--output"},
        description = "Output file for the report (optional, defaults to stdout)"
    )
    private String outputFile;

    @Override
    public Integer call() {
        PrintWriter out = new PrintWriter(System.out, true);

        try {
            // Validate input
            if (specLocation == null || specLocation.trim().isEmpty()) {
                out.println("ERROR: Specification location is required.");
                out.println("Usage: api-security-analyzer [OPTIONS] <spec-file-or-url>");
                return 1;
            }

            // Parse and validate mode
            AnalysisReport.AnalysisMode analysisMode;
            try {
                analysisMode = parseMode(mode);
            } catch (IllegalArgumentException e) {
                out.println("ERROR: " + e.getMessage());
                out.println("Valid modes: static, active, both, contract");
                return 1;
            }

            // Note: baseUrl validation moved to UnifiedAnalyzer
            // It will try to extract from spec first, then use --base-url override

            // Parse crypto protocol
            HttpClient.CryptoProtocol protocol = parseCryptoProtocol(cryptoProtocol);

            // Parse report format
            ReportFormat reportFormat = parseFormat(format);

            if (verbose) {
                out.println("Configuration:");
                out.println("  Mode: " + analysisMode);
                out.println("  Specification: " + specLocation);
                if (baseUrl != null) {
                    out.println("  Base URL: " + baseUrl);
                }
                out.println("  Crypto Protocol: " + protocol.getDisplayName());
                out.println("  Format: " + reportFormat);
                out.println();
            }

            // Configure analyzer
            UnifiedAnalyzer.AnalyzerConfig config = UnifiedAnalyzer.AnalyzerConfig.builder()
                .mode(analysisMode)
                .baseUrl(baseUrl)
                .authHeader(authHeader)
                .cryptoProtocol(protocol)
                .verifySsl(!noVerifySsl)
                .verbose(verbose)
                .noFuzzing(noFuzzing)
                .build();

            // Perform analysis
            UnifiedAnalyzer analyzer = new UnifiedAnalyzer(config);
            AnalysisReport report = analyzer.analyze(specLocation);

            // Generate report
            Reporter reporter = ReporterFactory.createReporter(reportFormat, !noColor);

            if (outputFile != null) {
                try (PrintWriter fileWriter = new PrintWriter(new FileWriter(outputFile))) {
                    reporter.generate(report, fileWriter);
                    out.println("Report written to: " + outputFile);
                }
            } else {
                reporter.generate(report, out);
            }

            // Return appropriate exit code
            return calculateExitCode(report);

        } catch (Exception e) {
            out.println("ERROR: Unexpected error occurred: " + e.getMessage());
            if (verbose) {
                e.printStackTrace(out);
            }
            return 99; // Unexpected error
        }
    }

    private AnalysisReport.AnalysisMode parseMode(String mode) {
        if (mode == null || mode.equalsIgnoreCase("static")) {
            return AnalysisReport.AnalysisMode.STATIC_ONLY;
        } else if (mode.equalsIgnoreCase("active")) {
            return AnalysisReport.AnalysisMode.ACTIVE_ONLY;
        } else if (mode.equalsIgnoreCase("both") || mode.equalsIgnoreCase("combined")) {
            return AnalysisReport.AnalysisMode.COMBINED;
        } else if (mode.equalsIgnoreCase("contract")) {
            return AnalysisReport.AnalysisMode.CONTRACT;
        } else {
            throw new IllegalArgumentException("Invalid mode: " + mode);
        }
    }

    private HttpClient.CryptoProtocol parseCryptoProtocol(String protocol) {
        if (protocol == null || protocol.equalsIgnoreCase("standard")) {
            return HttpClient.CryptoProtocol.STANDARD_TLS;
        } else if (protocol.equalsIgnoreCase("gost") || protocol.equalsIgnoreCase("cryptopro")) {
            return HttpClient.CryptoProtocol.CRYPTOPRO_JCSP;
        } else {
            return HttpClient.CryptoProtocol.STANDARD_TLS;
        }
    }

    private ReportFormat parseFormat(String format) {
        if (format == null || format.equalsIgnoreCase("console")) {
            return ReportFormat.CONSOLE;
        } else if (format.equalsIgnoreCase("json")) {
            return ReportFormat.JSON;
        } else {
            return ReportFormat.CONSOLE;
        }
    }

    private int calculateExitCode(AnalysisReport report) {
        int totalIssues = report.getTotalIssueCount();

        if (totalIssues == 0) {
            return 0; // Success, no issues
        }

        // Check for critical/high severity issues
        boolean hasCriticalOrHigh = false;

        if (report.hasStaticResults() && !report.getStaticResult().hasError()) {
            hasCriticalOrHigh = report.getStaticResult().getFindings().stream()
                .anyMatch(f -> f.getSeverity().isCriticalOrHigh());
        }

        if (!hasCriticalOrHigh && report.hasActiveResults() && !report.getActiveResult().hasError()) {
            hasCriticalOrHigh = report.getActiveResult().getReport().getAllVulnerabilities().stream()
                .anyMatch(v -> v.getSeverity().isCriticalOrHigh());
        }

        if (!hasCriticalOrHigh && report.hasContractResults() && !report.getContractResult().hasError()) {
            hasCriticalOrHigh = report.getContractResult().getReport().hasCriticalIssues();
        }

        return hasCriticalOrHigh ? 3 : 0;
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new ApiSecurityAnalyzerCli()).execute(args);
        System.exit(exitCode);
    }
}
