package active.scanner.infodisclosure;

import active.http.HttpClient;
import active.model.ApiEndpoint;
import active.model.TestRequest;
import active.model.TestResponse;
import active.model.VulnerabilityReport;
import active.scanner.AbstractScanner;
import active.scanner.ScanContext;
import active.scanner.ScanResult;
import active.scanner.ScannerConfig;
import model.Severity;

import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Scanner for detecting Information Disclosure vulnerabilities.
 *
 * <p>Information Disclosure occurs when an API exposes sensitive data
 * that should be protected, allowing attackers to gather intelligence
 * for further attacks or directly access confidential information.
 *
 * <p>This scanner tests for:
 * <ul>
 *   <li>API keys, secrets, and tokens in responses</li>
 *   <li>Private keys and certificates</li>
 *   <li>Database credentials and connection strings</li>
 *   <li>Internal IP addresses and infrastructure details</li>
 *   <li>Personally Identifiable Information (PII) without masking</li>
 *   <li>Debug/trace information in production</li>
 *   <li>Source code fragments and comments</li>
 *   <li>Backup files and temporary files</li>
 * </ul>
 *
 * <p>Based on OWASP API Security Top 10 - API6:2023
 */
public final class InformationDisclosureScanner extends AbstractScanner {
    private static final String SCANNER_ID = "information-disclosure-scanner";
    private static final String SCANNER_NAME = "Information Disclosure Scanner";
    private static final String SCANNER_DESCRIPTION =
        "Detects sensitive information leakage including API keys, secrets, PII, and internal details";

    // Patterns for detecting sensitive information
    private static final Map<String, Pattern> SENSITIVE_PATTERNS = Map.ofEntries(
        Map.entry("API Key", Pattern.compile("(?i)(api[_-]?key|apikey)[\"']?\\s*[:=]\\s*[\"']?([a-zA-Z0-9_\\-]{20,})")),
        Map.entry("AWS Key", Pattern.compile("(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")),
        Map.entry("JWT Token", Pattern.compile("eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}")),
        Map.entry("Private Key", Pattern.compile("-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----")),
        Map.entry("SSH Key", Pattern.compile("-----BEGIN OPENSSH PRIVATE KEY-----")),
        Map.entry("Password", Pattern.compile("(?i)(password|passwd|pwd)[\"']?\\s*[:=]\\s*[\"']([^\"'\\s]{6,})[\"']?")),
        Map.entry("Database URL", Pattern.compile("(?i)(mongodb|mysql|postgresql|redis)://[^\\s\"'<>]+")),
        Map.entry("Secret", Pattern.compile("(?i)(secret|token|auth)[_-]?(key)?[\"']?\\s*[:=]\\s*[\"']([a-zA-Z0-9_\\-]{16,})")),
        Map.entry("Bearer Token", Pattern.compile("Bearer\\s+[a-zA-Z0-9_\\-\\.]{20,}")),
        Map.entry("GitHub Token", Pattern.compile("ghp_[a-zA-Z0-9]{36}")),
        Map.entry("Google API Key", Pattern.compile("AIza[0-9A-Za-z_\\-]{35}")),
        Map.entry("Slack Token", Pattern.compile("xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}")),
        Map.entry("Credit Card", Pattern.compile("\\b(?:\\d[ -]*?){13,16}\\b")),
        Map.entry("SSN", Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b")),
        Map.entry("Email", Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")),
        Map.entry("IPv4 Address", Pattern.compile("\\b(?:10|172\\.(?:1[6-9]|2[0-9]|3[01])|192\\.168)\\.\\d{1,3}\\.\\d{1,3}\\b")),
        Map.entry("Connection String", Pattern.compile("(?i)(Server|Data Source|Host)\\s*=.*?(Password|PWD)\\s*=")),
        Map.entry("Access Token", Pattern.compile("(?i)access[_-]?token[\"']?\\s*[:=]\\s*[\"']([a-zA-Z0-9_\\-\\.]{20,})"))
    );

    // Common backup file extensions
    private static final List<String> BACKUP_EXTENSIONS = List.of(
        ".bak", ".backup", ".old", ".tmp", ".temp", ".swp",
        ".save", ".orig", "~", ".copy", ".db", ".sql"
    );

    // Debug/trace keywords
    private static final List<String> DEBUG_KEYWORDS = List.of(
        "debug_mode", "trace_id", "stack_trace", "DEBUG:", "TRACE:",
        "development_mode", "test_mode", "verbose_logging"
    );

    public InformationDisclosureScanner() {
        super();
    }

    public InformationDisclosureScanner(ScannerConfig config) {
        super(config);
    }

    @Override
    public String getId() {
        return SCANNER_ID;
    }

    @Override
    public String getName() {
        return SCANNER_NAME;
    }

    @Override
    public String getDescription() {
        return SCANNER_DESCRIPTION;
    }

    @Override
    public List<VulnerabilityReport.VulnerabilityType> getDetectedVulnerabilities() {
        return List.of(VulnerabilityReport.VulnerabilityType.EXCESSIVE_DATA_EXPOSURE);
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // Apply to all endpoints, especially GET requests that return data
        return true;
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int totalTests = 0;

        // Test Case 1: Scan response for sensitive data patterns
        InfoDisclosureTestResult sensitiveDataTest = testSensitiveDataExposure(endpoint, httpClient, context);
        totalTests += sensitiveDataTest.testsExecuted();
        vulnerabilities.addAll(sensitiveDataTest.vulnerabilities());

        // Test Case 2: Check for debug/trace information
        InfoDisclosureTestResult debugInfoTest = testDebugInformation(endpoint, httpClient, context);
        totalTests += debugInfoTest.testsExecuted();
        vulnerabilities.addAll(debugInfoTest.vulnerabilities());

        // Test Case 3: Check for backup files
        InfoDisclosureTestResult backupFilesTest = testBackupFiles(endpoint, httpClient, context);
        totalTests += backupFilesTest.testsExecuted();
        vulnerabilities.addAll(backupFilesTest.vulnerabilities());

        // Test Case 4: Excessive data exposure
        InfoDisclosureTestResult excessiveDataTest = testExcessiveDataExposure(endpoint, httpClient, context);
        totalTests += excessiveDataTest.testsExecuted();
        vulnerabilities.addAll(excessiveDataTest.vulnerabilities());

        return createSuccessResult(endpoint, vulnerabilities, totalTests, startTime);
    }

    /**
     * Test for sensitive data patterns in API response.
     */
    private InfoDisclosureTestResult testSensitiveDataExposure(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing sensitive data exposure for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Sensitive Data Pattern Scan");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        String body = response.getBody();

        if (body == null || body.isEmpty()) {
            return new InfoDisclosureTestResult(vulnerabilities, 1);
        }

        Map<String, List<String>> detectedSecrets = new HashMap<>();

        // Scan for each sensitive pattern
        for (Map.Entry<String, Pattern> entry : SENSITIVE_PATTERNS.entrySet()) {
            var matcher = entry.getValue().matcher(body);
            List<String> matches = new ArrayList<>();

            while (matcher.find() && matches.size() < 5) {  // Limit to 5 matches per pattern
                String match = matcher.group().length() > 100
                    ? matcher.group().substring(0, 100) + "..."
                    : matcher.group();
                matches.add(match);
            }

            if (!matches.isEmpty()) {
                detectedSecrets.put(entry.getKey(), matches);
            }
        }

        if (!detectedSecrets.isEmpty()) {
            Severity severity = determineSeverityForSecrets(detectedSecrets);

            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.EXCESSIVE_DATA_EXPOSURE)
                .severity(severity)
                .endpoint(endpoint)
                .title("Sensitive Information Disclosure in API Response")
                .description(
                    "The API response contains sensitive information that should not be exposed. " +
                    "Detected: " + String.join(", ", detectedSecrets.keySet()) + ". " +
                    "This information can be used by attackers to compromise the system or user accounts."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("detectedSecrets", detectedSecrets)
                .addEvidence("responseSize", body.length())
                .addRecommendation("Remove all sensitive data from API responses")
                .addRecommendation("Use environment variables for secrets, never hardcode them")
                .addRecommendation("Implement proper data filtering before sending responses")
                .addRecommendation("Mask or redact sensitive information (PII, credentials)")
                .addRecommendation("Review and sanitize all API responses")
                .reproductionSteps(
                    "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                    "2. Examine response body\n" +
                    "3. Observe sensitive data: " + detectedSecrets.keySet()
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        return new InfoDisclosureTestResult(vulnerabilities, 1);
    }

    /**
     * Test for debug/trace information leakage.
     */
    private InfoDisclosureTestResult testDebugInformation(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing debug information disclosure for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        // Try with debug parameter
        TestRequest request = TestRequest.builder()
            .url(url + (url.contains("?") ? "&" : "?") + "debug=true")
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Debug Information Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        String body = response.getBody();

        if (body == null || body.isEmpty()) {
            return new InfoDisclosureTestResult(vulnerabilities, 1);
        }

        List<String> foundDebugInfo = new ArrayList<>();

        for (String keyword : DEBUG_KEYWORDS) {
            if (body.toLowerCase().contains(keyword.toLowerCase())) {
                foundDebugInfo.add(keyword);
            }
        }

        // Check for common debug headers
        Map<String, String> debugHeaders = new HashMap<>();
        for (Map.Entry<String, List<String>> header : response.getHeaders().entrySet()) {
            String headerName = header.getKey().toLowerCase();
            if (headerName.contains("debug") || headerName.contains("trace") ||
                headerName.contains("x-request-id") || headerName.contains("x-correlation-id")) {
                debugHeaders.put(header.getKey(), String.join(",", header.getValue()));
            }
        }

        if (!foundDebugInfo.isEmpty() || !debugHeaders.isEmpty()) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.EXCESSIVE_DATA_EXPOSURE)
                .severity(Severity.LOW)
                .endpoint(endpoint)
                .title("Debug/Trace Information Disclosure")
                .description(
                    "The API exposes debug or trace information that should only be available in development. " +
                    "Found debug keywords: " + foundDebugInfo + ", debug headers: " + debugHeaders.keySet() + ". " +
                    "This information can help attackers understand the application internals."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("debugKeywords", foundDebugInfo)
                .addEvidence("debugHeaders", debugHeaders)
                .addRecommendation("Disable debug mode in production")
                .addRecommendation("Remove debug parameters from production APIs")
                .addRecommendation("Implement proper logging without exposing debug info to clients")
                .addRecommendation("Use feature flags to control debug functionality")
                .reproductionSteps(
                    "1. Send request to " + url + " with debug=true parameter\n" +
                    "2. Observe debug information in response\n" +
                    "3. Debug data: " + foundDebugInfo
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        return new InfoDisclosureTestResult(vulnerabilities, 1);
    }

    /**
     * Test for accessible backup files.
     */
    private InfoDisclosureTestResult testBackupFiles(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing backup file exposure for: " + endpoint);

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int testsExecuted = 0;
        String basePath = endpoint.getPath();

        for (String extension : BACKUP_EXTENSIONS) {
            String url = context.buildUrl(basePath + extension);

            TestRequest request = TestRequest.builder()
                .url(url)
                .method("GET")
                .headers(context.getAuthHeaders())
                .build();

            TestResponse response = executeTest(httpClient, request, "Backup File Check: " + extension);
            testsExecuted++;

            // If backup file is accessible
            if (response.getStatusCode() == 200 && response.getBody() != null && !response.getBody().isEmpty()) {
                VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                    .type(VulnerabilityReport.VulnerabilityType.EXCESSIVE_DATA_EXPOSURE)
                    .severity(Severity.HIGH)
                    .endpoint(endpoint)
                    .title("Accessible Backup File: " + extension)
                    .description(
                        "A backup file with extension '" + extension + "' is accessible at " + url + ". " +
                        "Backup files often contain sensitive data, source code, or configuration details " +
                        "that should not be publicly accessible."
                    )
                    .exploitRequest(request)
                    .exploitResponse(response)
                    .addEvidence("backupExtension", extension)
                    .addEvidence("fileSize", response.getBody().length())
                    .addEvidence("statusCode", 200)
                    .addRecommendation("Remove all backup files from production servers")
                    .addRecommendation("Configure web server to deny access to backup file extensions")
                    .addRecommendation("Use .gitignore to prevent committing backup files")
                    .addRecommendation("Implement automated cleanup of temporary/backup files")
                    .reproductionSteps(
                        "1. Send GET request to " + url + "\n" +
                        "2. Observe 200 OK response with file content\n" +
                        "3. Backup file is publicly accessible"
                    )
                    .build();

                vulnerabilities.add(vulnerability);
            }
        }

        return new InfoDisclosureTestResult(vulnerabilities, testsExecuted);
    }

    /**
     * Test for excessive data exposure (more fields than necessary).
     */
    private InfoDisclosureTestResult testExcessiveDataExposure(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing excessive data exposure for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Excessive Data Exposure Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        String body = response.getBody();

        if (body == null || body.isEmpty() || !body.trim().startsWith("{")) {
            return new InfoDisclosureTestResult(vulnerabilities, 1);
        }

        // Check for common internal fields that should not be exposed
        List<String> sensitiveFields = List.of(
            "\"password\":", "\"passwordHash\":", "\"salt\":",
            "\"internal_id\":", "\"user_id\":", "\"account_id\":",
            "\"created_by\":", "\"updated_by\":", "\"deleted_at\":",
            "\"is_admin\":", "\"is_superuser\":", "\"role\":",
            "\"permissions\":", "\"access_level\":", "\"token\":",
            "\"secret\":", "\"private_key\":", "\"api_key\":"
        );

        List<String> exposedFields = new ArrayList<>();
        for (String field : sensitiveFields) {
            if (body.toLowerCase().contains(field.toLowerCase())) {
                exposedFields.add(field.replace("\":", "").replace("\"", ""));
            }
        }

        if (!exposedFields.isEmpty()) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.EXCESSIVE_DATA_EXPOSURE)
                .severity(Severity.MEDIUM)
                .endpoint(endpoint)
                .title("Excessive Data Exposure - Internal Fields")
                .description(
                    "The API response exposes internal fields that should not be visible to clients. " +
                    "Exposed fields: " + exposedFields + ". " +
                    "This violates the principle of least privilege and may expose sensitive implementation details."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("exposedFields", exposedFields)
                .addEvidence("responseSize", body.length())
                .addRecommendation("Use Data Transfer Objects (DTOs) to control exposed fields")
                .addRecommendation("Implement field-level access control")
                .addRecommendation("Remove internal fields from API responses")
                .addRecommendation("Use serialization annotations to exclude sensitive fields")
                .addRecommendation("Follow principle of least privilege - only return necessary data")
                .reproductionSteps(
                    "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                    "2. Examine response body\n" +
                    "3. Observe internal fields: " + exposedFields
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        return new InfoDisclosureTestResult(vulnerabilities, 1);
    }

    /**
     * Determine severity based on types of secrets detected.
     */
    private Severity determineSeverityForSecrets(Map<String, List<String>> detectedSecrets) {
        Set<String> secretTypes = detectedSecrets.keySet();

        // Critical: Private keys, AWS keys, database credentials
        if (secretTypes.contains("Private Key") ||
            secretTypes.contains("SSH Key") ||
            secretTypes.contains("AWS Key") ||
            secretTypes.contains("Database URL") ||
            secretTypes.contains("Connection String")) {
            return Severity.CRITICAL;
        }

        // High: API keys, passwords, tokens
        if (secretTypes.contains("API Key") ||
            secretTypes.contains("Password") ||
            secretTypes.contains("Secret") ||
            secretTypes.contains("Bearer Token") ||
            secretTypes.contains("GitHub Token")) {
            return Severity.HIGH;
        }

        // Medium: PII like credit cards, SSN
        if (secretTypes.contains("Credit Card") ||
            secretTypes.contains("SSN")) {
            return Severity.HIGH;
        }

        // Default to MEDIUM for other sensitive data
        return Severity.MEDIUM;
    }

    /**
     * Result of an information disclosure test case.
     */
    private record InfoDisclosureTestResult(
        List<VulnerabilityReport> vulnerabilities,
        int testsExecuted
    ) {}
}
