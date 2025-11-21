package com.apisecurity.analyzer.core.i18n;

/**
 * Constants for internationalization message keys.
 * This class provides type-safe access to message keys used throughout the application.
 */
public final class I18nKeys {

    private I18nKeys() {
        // Private constructor to prevent instantiation
    }

    // Common keys
    public static final String COMMON_ERROR = "common.error";
    public static final String COMMON_WARNING = "common.warning";
    public static final String COMMON_SUCCESS = "common.success";
    public static final String COMMON_INFO = "common.info";

    // Vulnerability types
    public static final String VULN_BOLA = "vulnerability.type.bola";
    public static final String VULN_BFLA = "vulnerability.type.bfla";
    public static final String VULN_BOPLA = "vulnerability.type.bopla";
    public static final String VULN_SQLI = "vulnerability.type.sqli";
    public static final String VULN_XSS = "vulnerability.type.xss";
    public static final String VULN_XXE = "vulnerability.type.xxe";
    public static final String VULN_SSRF = "vulnerability.type.ssrf";
    public static final String VULN_MASS_ASSIGNMENT = "vulnerability.type.mass_assignment";
    public static final String VULN_SECURITY_MISCONFIGURATION = "vulnerability.type.security_misconfiguration";
    public static final String VULN_SENSITIVE_DATA_EXPOSURE = "vulnerability.type.sensitive_data_exposure";

    // Severity levels
    public static final String SEVERITY_CRITICAL = "severity.critical";
    public static final String SEVERITY_HIGH = "severity.high";
    public static final String SEVERITY_MEDIUM = "severity.medium";
    public static final String SEVERITY_LOW = "severity.low";
    public static final String SEVERITY_INFO = "severity.info";

    // Scanner messages
    public static final String SCANNER_STARTING = "scanner.starting";
    public static final String SCANNER_COMPLETED = "scanner.completed";
    public static final String SCANNER_FAILED = "scanner.failed";
    public static final String SCANNER_SKIPPED = "scanner.skipped";

    // Report messages
    public static final String REPORT_TITLE = "report.title";
    public static final String REPORT_SUMMARY = "report.summary";
    public static final String REPORT_VULNERABILITIES_FOUND = "report.vulnerabilities.found";
    public static final String REPORT_NO_VULNERABILITIES = "report.no.vulnerabilities";
    public static final String REPORT_RECOMMENDATIONS = "report.recommendations";

    // CLI messages
    public static final String CLI_WELCOME = "cli.welcome";
    public static final String CLI_ANALYSIS_STARTED = "cli.analysis.started";
    public static final String CLI_ANALYSIS_COMPLETED = "cli.analysis.completed";
    public static final String CLI_INVALID_INPUT = "cli.invalid.input";

    // Web UI messages
    public static final String WEBUI_TITLE = "webui.title";
    public static final String WEBUI_START_ANALYSIS = "webui.start.analysis";
    public static final String WEBUI_STOP_ANALYSIS = "webui.stop.analysis";
    public static final String WEBUI_CONFIGURATION = "webui.configuration";
    public static final String WEBUI_RESULTS = "webui.results";
}
