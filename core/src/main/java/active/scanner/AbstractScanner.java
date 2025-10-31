package active.scanner;

import active.http.HttpClient;
import active.model.ApiEndpoint;
import active.model.TestRequest;
import active.model.TestResponse;
import active.model.VulnerabilityReport;

import java.time.Instant;
import java.util.*;
import java.util.logging.Logger;

/**
 * Abstract base class for vulnerability scanners.
 * Provides common functionality and reduces boilerplate for scanner implementations.
 *
 * <p>Subclasses should:
 * <ul>
 *   <li>Define scanner metadata (ID, name, description)</li>
 *   <li>Implement {@link #isApplicable(ApiEndpoint)} to filter endpoints</li>
 *   <li>Implement {@link #performScan(ApiEndpoint, HttpClient, ScanContext)} with test logic</li>
 * </ul>
 */
public abstract class AbstractScanner implements VulnerabilityScanner {
    protected final Logger logger = Logger.getLogger(getClass().getName());
    protected ScannerConfig config;

    protected AbstractScanner() {
        this.config = ScannerConfig.defaultConfig();
    }

    protected AbstractScanner(ScannerConfig config) {
        this.config = config != null ? config : ScannerConfig.defaultConfig();
    }

    @Override
    public final ScanResult scan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();

        try {
            logger.info("Starting " + getName() + " scan on: " + endpoint);

            // Delegate to subclass implementation
            return performScan(endpoint, httpClient, context);

        } catch (Exception e) {
            logger.warning(getName() + " scan failed for " + endpoint + ": " + e.getMessage());

            return ScanResult.builder()
                .scannerId(getId())
                .endpoint(endpoint)
                .status(ScanResult.ScanStatus.FAILED)
                .startTime(startTime)
                .endTime(Instant.now())
                .errorMessage("Scan failed: " + e.getMessage())
                .build();
        }
    }

    /**
     * Perform the actual vulnerability scan.
     * Subclasses implement this method with their specific test logic.
     *
     * @param endpoint the endpoint to scan
     * @param httpClient the HTTP client to use for testing
     * @param context the scan context with configuration and state
     * @return scan result with detected vulnerabilities
     */
    protected abstract ScanResult performScan(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    );

    @Override
    public ScannerConfig getConfig() {
        return config;
    }

    @Override
    public void setConfig(ScannerConfig config) {
        this.config = config != null ? config : ScannerConfig.defaultConfig();
    }

    /**
     * Helper method to create a successful scan result.
     *
     * @param endpoint the scanned endpoint
     * @param vulnerabilities list of discovered vulnerabilities
     * @param totalTests total number of tests executed
     * @param startTime scan start time
     * @return scan result
     */
    protected ScanResult createSuccessResult(
        ApiEndpoint endpoint,
        List<VulnerabilityReport> vulnerabilities,
        int totalTests,
        Instant startTime
    ) {
        return ScanResult.builder()
            .scannerId(getId())
            .endpoint(endpoint)
            .status(ScanResult.ScanStatus.SUCCESS)
            .vulnerabilities(vulnerabilities)
            .totalTests(totalTests)
            .failedTests(0)
            .startTime(startTime)
            .endTime(Instant.now())
            .build();
    }

    /**
     * Helper to check if response indicates successful authentication bypass.
     *
     * @param response the HTTP response
     * @return true if the response suggests successful unauthorized access
     */
    protected boolean isSuccessfulUnauthorizedAccess(TestResponse response) {
        int status = response.getStatusCode();
        // 200 OK, 201 Created, or any 2xx status (except 204 No Content which might be normal)
        return status >= 200 && status < 300 && status != 204;
    }

    /**
     * Helper to check if response indicates authentication is required.
     *
     * @param response the HTTP response
     * @return true if the response indicates missing/invalid authentication
     */
    protected boolean isAuthenticationRequired(TestResponse response) {
        int status = response.getStatusCode();
        // 401 Unauthorized or 403 Forbidden
        return status == 401 || status == 403;
    }

    /**
     * Helper to execute a test request and log the result.
     *
     * @param httpClient the HTTP client
     * @param request the test request
     * @param testName name of the test for logging
     * @return the response
     */
    protected TestResponse executeTest(HttpClient httpClient, TestRequest request, String testName) {
        logger.fine("Executing test: " + testName);
        return httpClient.execute(request);
    }
}
