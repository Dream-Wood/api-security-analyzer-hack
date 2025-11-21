package cli;

import active.http.HttpClient;
import com.apisecurity.analyzer.core.i18n.LocaleManager;
import com.apisecurity.analyzer.core.i18n.MessageService;
import report.AnalysisReport;
import report.ReportFormat;
import report.Reporter;
import report.ReporterFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import util.CryptoProtocolParser;
import util.ModeParser;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.concurrent.Callable;

/**
 * Главная точка входа CLI для API Security Analyzer.
 * Использует библиотеку picocli для парсинга аргументов командной строки.
 *
 * <p>Поддерживаемые режимы анализа:
 * <ul>
 *   <li><b>static</b> - статический анализ спецификации без выполнения запросов</li>
 *   <li><b>active</b> - активное тестирование безопасности с реальными HTTP запросами</li>
 *   <li><b>both/combined</b> - комбинированный анализ (статический + активный)</li>
 *   <li><b>contract</b> - проверка соответствия реализации контракту API</li>
 *   <li><b>full</b> - полный анализ (все виды тестов)</li>
 * </ul>
 *
 * <p>Примеры использования:
 * <pre>
 * # Статический анализ
 * api-security-analyzer spec.yaml
 *
 * # Активное тестирование с указанием базового URL
 * api-security-analyzer -m active -u https://api.example.com spec.yaml
 *
 * # Полный анализ с поддержкой ГОСТ криптографии
 * api-security-analyzer -m full -c gost --gost-pfx-path cert.pfx spec.yaml
 *
 * # ГОСТ с обходом hostname verification (IP+SNI техника)
 * api-security-analyzer -m active -c gost --gost-pfx-path cert.pfx \
 *   --server-ip 45.84.153.123 --sni-hostname localhost \
 *   -u https://api.gost.bankingapi.ru:8443 spec.yaml
 * </pre>
 *
 * @author API Security Analyzer Team
 * @since 1.0
 */
@Command(
    name = "api-security-analyzer",
    description = "Анализ OpenAPI/AsyncAPI спецификаций на уязвимости безопасности и проблемы соответствия стандартам",
    mixinStandardHelpOptions = true,
    version = "1.0-SNAPSHOT"
)
public class ApiSecurityAnalyzerCli implements Callable<Integer> {

    @Parameters(
        index = "0",
        description = "Path to OpenAPI/AsyncAPI specification file (YAML/JSON) or URL"
    )
    private String specLocation;

    @Option(
        names = {"-m", "--mode"},
        description = "Analysis mode: static, active, both, contract, full (default: static)",
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
        names = {"--gost-pfx-path"},
        description = "Path to PFX certificate file for GOST TLS (e.g., certs/cert.pfx)"
    )
    private String gostPfxPath;

    @Option(
        names = {"--gost-pfx-password"},
        description = "Password for PFX certificate (use with --gost-pfx-path)"
    )
    private String gostPfxPassword;

    @Option(
        names = {"--gost-pfx-resource"},
        description = "Treat PFX path as classpath resource (default: false)"
    )
    private boolean gostPfxResource;

    @Option(
        names = {"--server-ip"},
        description = "Server IP address for GOST TLS bypass (use with --sni-hostname)"
    )
    private String serverIp;

    @Option(
        names = {"--sni-hostname"},
        description = "SNI hostname for GOST TLS bypass (hostname from certificate SAN)"
    )
    private String sniHostname;

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
        names = {"-l", "--lang", "--language"},
        description = "Language for output: en, ru (default: system locale)"
    )
    private String language;

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

    @Option(
        names = {"--no-auto-auth"},
        description = "Disable automatic authentication"
    )
    private boolean noAutoAuth;

    @Option(
        names = {"--no-test-users"},
        description = "Disable creation of test users for BOLA testing"
    )
    private boolean noTestUsers;

    @Option(
        names = {"--max-parallel-scans"},
        description = "Maximum number of parallel scans (default: 4)"
    )
    private Integer maxParallelScans;

    @Option(
        names = {"--request-delay"},
        description = "Delay in milliseconds between requests (default: depends on scan intensity). Use higher values (e.g., 500-1000ms) to reduce load on the backend."
    )
    private Integer requestDelayMs;

    // === Discovery Options ===

    @Option(
        names = {"--enable-discovery"},
        description = "Enable endpoint discovery to find undocumented endpoints"
    )
    private boolean enableDiscovery;

    @Option(
        names = {"--discovery-strategy"},
        description = "Discovery strategy: none, top-down, bottom-up, hybrid (default: none)"
    )
    private String discoveryStrategy;

    @Option(
        names = {"--discovery-max-depth"},
        description = "Maximum depth for discovery (default: 5)"
    )
    private Integer discoveryMaxDepth;

    @Option(
        names = {"--discovery-max-requests"},
        description = "Maximum total requests for discovery (default: 1000)"
    )
    private Integer discoveryMaxRequests;

    @Option(
        names = {"--discovery-fast-cancel"},
        description = "Stop immediately when dangerous undocumented endpoint found"
    )
    private boolean discoveryFastCancel;

    @Option(
        names = {"--wordlist-dir"},
        description = "Directory with wordlist files (default: ./wordlists)"
    )
    private String wordlistDir;

    @Override
    public Integer call() {
        PrintWriter out = new PrintWriter(System.out, true);

        try {
            // Initialize localization
            if (language != null && !language.isBlank()) {
                try {
                    LocaleManager.setCurrentLocale(language);
                    if (verbose) {
                        out.println(MessageService.getMessage("cli.language.set", language));
                    }
                } catch (IllegalArgumentException e) {
                    out.println(MessageService.getMessage("cli.language.unsupported", language));
                    return 1;
                }
            }

            // Validate input
            if (specLocation == null || specLocation.trim().isEmpty()) {
                out.println("ERROR: Specification location is required.");
                out.println("Usage: api-security-analyzer [OPTIONS] <spec-file-or-url>");
                return 1;
            }

            // Parse and validate mode using centralized ModeParser utility
            AnalysisReport.AnalysisMode analysisMode;
            try {
                analysisMode = ModeParser.parse(mode);
            } catch (IllegalArgumentException e) {
                out.println("ERROR: " + e.getMessage());
                out.println("Valid modes: static, active, both, contract, full");
                return 1;
            }

            // Note: baseUrl validation moved to UnifiedAnalyzer
            // It will try to extract from spec first, then use --base-url override

            // Parse crypto protocol using centralized CryptoProtocolParser utility
            HttpClient.CryptoProtocol protocol = CryptoProtocolParser.parse(cryptoProtocol);

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
            UnifiedAnalyzer.AnalyzerConfig.Builder configBuilder = UnifiedAnalyzer.AnalyzerConfig.builder()
                .mode(analysisMode)
                .baseUrl(baseUrl)
                .authHeader(authHeader)
                .cryptoProtocol(protocol)
                .verifySsl(!noVerifySsl)
                .gostPfxPath(gostPfxPath)
                .gostPfxPassword(gostPfxPassword)
                .gostPfxResource(gostPfxResource)
                .verbose(verbose)
                .noFuzzing(noFuzzing)
                .autoAuth(!noAutoAuth)
                .createTestUsers(!noTestUsers);

            // Configure IP+SNI for GOST TLS hostname bypass
            if (serverIp != null && sniHostname != null) {
                configBuilder
                    .useLowLevelSocket(true)
                    .targetIP(serverIp)
                    .sniHostname(sniHostname);
                if (verbose) {
                    out.println("  GOST TLS bypass enabled:");
                    out.println("    Server IP: " + serverIp);
                    out.println("    SNI Hostname: " + sniHostname);
                }
            }

            // Configure endpoint discovery
            if (enableDiscovery || discoveryStrategy != null) {
                String strategy = discoveryStrategy != null ? discoveryStrategy : "hybrid";
                configBuilder
                    .enableDiscovery(true)
                    .discoveryStrategy(strategy)
                    .discoveryMaxDepth(discoveryMaxDepth != null ? discoveryMaxDepth : 5)
                    .discoveryMaxRequests(discoveryMaxRequests != null ? discoveryMaxRequests : 1000)
                    .discoveryFastCancel(discoveryFastCancel)
                    .wordlistDir(wordlistDir != null ? wordlistDir : "./wordlists");

                if (verbose) {
                    out.println("  Discovery enabled:");
                    out.println("    Strategy: " + strategy);
                    out.println("    Max Depth: " + (discoveryMaxDepth != null ? discoveryMaxDepth : 5));
                    out.println("    Max Requests: " + (discoveryMaxRequests != null ? discoveryMaxRequests : 1000));
                    out.println("    Fast Cancel: " + discoveryFastCancel);
                    out.println("    Wordlist Dir: " + (wordlistDir != null ? wordlistDir : "./wordlists"));
                }
            }

            // Set max parallel scans if provided
            if (maxParallelScans != null && maxParallelScans > 0) {
                configBuilder.maxParallelScans(maxParallelScans);
            }

            // Set request delay if provided
            if (requestDelayMs != null && requestDelayMs >= 0) {
                configBuilder.requestDelayMs(requestDelayMs);
                if (verbose) {
                    out.println("  Request Delay: " + requestDelayMs + "ms");
                }
            }

            UnifiedAnalyzer.AnalyzerConfig config = configBuilder.build();

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

        if (!hasCriticalOrHigh && report.hasActiveResults() && !report.getActiveResult().hasError()
                && report.getActiveResult().getReport() != null) {
            hasCriticalOrHigh = report.getActiveResult().getReport().getAllVulnerabilities().stream()
                .anyMatch(v -> v.getSeverity().isCriticalOrHigh());
        }

        if (!hasCriticalOrHigh && report.hasContractResults() && !report.getContractResult().hasError()
                && report.getContractResult().getReport() != null) {
            hasCriticalOrHigh = report.getContractResult().getReport().hasCriticalIssues();
        }

        return hasCriticalOrHigh ? 3 : 0;
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new ApiSecurityAnalyzerCli()).execute(args);
        System.exit(exitCode);
    }
}
