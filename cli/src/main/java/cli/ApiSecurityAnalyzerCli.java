package cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

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
                out.println("Usage: api-security-analyzer <spec-file-or-url>");
                return 1;
            }

            if (verbose) {
                out.println("Loading specification from: " + specLocation);
                out.println();
            }

            // Analyze the specification
            SpecAnalyzer analyzer = new SpecAnalyzer();
            SpecAnalyzer.AnalysisResult result = analyzer.analyze(specLocation);

            // Format and display results
            ResultFormatter formatter = new ResultFormatter(out, !noColor);
            formatter.printResult(result, specLocation);

            // Return appropriate exit code
            if (!result.isSuccessful()) {
                return 2; // Parsing/loading error
            }

            if (result.hasValidationFindings()) {
                // Check if there are any critical or high severity findings
                boolean hasCriticalOrHigh = result.getValidationFindings().stream()
                    .anyMatch(f -> f.getSeverity().isCriticalOrHigh());

                if (hasCriticalOrHigh) {
                    return 3; // Critical or high severity issues found
                }
                return 0; // Only medium/low/info issues found
            }

            return 0; // Success, no issues

        } catch (Exception e) {
            out.println("ERROR: Unexpected error occurred: " + e.getMessage());
            if (verbose) {
                e.printStackTrace(out);
            }
            return 99; // Unexpected error
        }
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new ApiSecurityAnalyzerCli()).execute(args);
        System.exit(exitCode);
    }
}
