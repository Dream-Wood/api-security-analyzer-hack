package active.validator;

import active.http.HttpClient;
import active.model.ApiEndpoint;
import active.validator.model.Divergence;
import active.validator.model.ValidationResult;
import io.swagger.v3.oas.models.OpenAPI;

import java.time.Instant;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Standalone engine for validating API contracts against OpenAPI specifications.
 *
 * <p>This is separate from vulnerability scanners and runs independently.
 * Use this for contract testing, CI/CD validation, and ensuring API compliance.
 *
 * <p>Example usage:
 * <pre>{@code
 * OpenAPI spec = loadOpenAPI();
 * ContractValidationEngine engine = new ContractValidationEngine(spec);
 *
 * // Configure
 * engine.setFuzzingEnabled(true);
 *
 * // Validate endpoints
 * ContractValidationReport report = engine.validate(endpoints, httpClient);
 *
 * // Check results
 * if (report.hasCriticalIssues()) {
 *     System.out.println("Contract validation failed!");
 * }
 * }</pre>
 */
public final class ContractValidationEngine {
    private static final Logger logger = Logger.getLogger(ContractValidationEngine.class.getName());

    private final OpenAPI openAPI;
    private final EndpointValidator endpointValidator;
    private boolean fuzzingEnabled;
    private final String baseUrl;

    /**
     * Create contract validation engine with OpenAPI specification.
     *
     * @param openAPI the OpenAPI specification to validate against
     */
    public ContractValidationEngine(OpenAPI openAPI) {
        this(openAPI, null, true);
    }

    /**
     * Create contract validation engine with configuration.
     *
     * @param openAPI the OpenAPI specification
     * @param fuzzingEnabled whether to enable fuzzing tests
     */
    public ContractValidationEngine(OpenAPI openAPI, boolean fuzzingEnabled) {
        this(openAPI, null, fuzzingEnabled);
    }

    /**
     * Create contract validation engine with base URL and configuration.
     *
     * @param openAPI the OpenAPI specification
     * @param baseUrl the base URL for endpoint testing
     * @param fuzzingEnabled whether to enable fuzzing tests
     */
    public ContractValidationEngine(OpenAPI openAPI, String baseUrl, boolean fuzzingEnabled) {
        this.openAPI = Objects.requireNonNull(openAPI, "OpenAPI spec cannot be null");
        this.baseUrl = baseUrl;
        this.fuzzingEnabled = fuzzingEnabled;
        this.endpointValidator = new EndpointValidator(openAPI, baseUrl, fuzzingEnabled);

        logger.info("Contract Validation Engine initialized" +
            (fuzzingEnabled ? " with fuzzing enabled" : " (fuzzing disabled)"));
    }

    /**
     * Validate a single endpoint.
     *
     * @param endpoint the endpoint to validate
     * @param httpClient HTTP client for testing
     * @return validation result
     */
    public ValidationResult validateEndpoint(ApiEndpoint endpoint, HttpClient httpClient) {
        logger.info("Validating endpoint: " + endpoint);
        return endpointValidator.validateEndpoint(endpoint, httpClient);
    }

    /**
     * Validate multiple endpoints and generate comprehensive report.
     *
     * @param endpoints list of endpoints to validate
     * @param httpClient HTTP client for testing
     * @return comprehensive validation report
     */
    public ContractValidationReport validate(List<ApiEndpoint> endpoints, HttpClient httpClient) {
        logger.info("Starting contract validation for " + endpoints.size() + " endpoints");

        Instant startTime = Instant.now();
        List<ValidationResult> results = endpointValidator.validateEndpoints(endpoints, httpClient);
        Instant endTime = Instant.now();

        ContractValidationReport report = new ContractValidationReport(
            results,
            startTime,
            endTime,
            fuzzingEnabled
        );

        logger.info("Contract validation completed: " +
            report.getTotalEndpoints() + " endpoints, " +
            report.getTotalDivergences() + " divergences found");

        return report;
    }

    /**
     * Quick validation - just checks if endpoints match specification.
     * No fuzzing, minimal testing.
     *
     * @param endpoints list of endpoints
     * @param httpClient HTTP client
     * @return validation report
     */
    public ContractValidationReport quickValidate(List<ApiEndpoint> endpoints, HttpClient httpClient) {
        boolean originalFuzzingSetting = this.fuzzingEnabled;

        try {
            setFuzzingEnabled(false);
            return validate(endpoints, httpClient);
        } finally {
            setFuzzingEnabled(originalFuzzingSetting);
        }
    }

    /**
     * Get statistics from the OpenAPI specification.
     *
     * @return specification statistics
     */
    public Map<String, Object> getSpecificationStats() {
        Map<String, Object> stats = new HashMap<>();

        if (openAPI.getPaths() != null) {
            stats.put("totalPaths", openAPI.getPaths().size());

            int totalOperations = openAPI.getPaths().values().stream()
                .mapToInt(pathItem -> {
                    int count = 0;
                    if (pathItem.getGet() != null) count++;
                    if (pathItem.getPost() != null) count++;
                    if (pathItem.getPut() != null) count++;
                    if (pathItem.getDelete() != null) count++;
                    if (pathItem.getPatch() != null) count++;
                    if (pathItem.getHead() != null) count++;
                    if (pathItem.getOptions() != null) count++;
                    return count;
                })
                .sum();

            stats.put("totalOperations", totalOperations);
        }

        if (openAPI.getComponents() != null && openAPI.getComponents().getSchemas() != null) {
            stats.put("totalSchemas", openAPI.getComponents().getSchemas().size());
        }

        if (openAPI.getInfo() != null) {
            stats.put("apiTitle", openAPI.getInfo().getTitle());
            stats.put("apiVersion", openAPI.getInfo().getVersion());
        }

        return stats;
    }

    /**
     * Enable or disable fuzzing tests.
     *
     * @param enabled true to enable fuzzing
     */
    public void setFuzzingEnabled(boolean enabled) {
        this.fuzzingEnabled = enabled;
        logger.info("Fuzzing " + (enabled ? "enabled" : "disabled"));
    }

    /**
     * Check if fuzzing is enabled.
     *
     * @return true if fuzzing is enabled
     */
    public boolean isFuzzingEnabled() {
        return fuzzingEnabled;
    }

    /**
     * Comprehensive validation report.
     */
    public static final class ContractValidationReport {
        private final List<ValidationResult> results;
        private final Instant startTime;
        private final Instant endTime;
        private final boolean fuzzingEnabled;
        private final Map<String, Object> statistics;

        private ContractValidationReport(
            List<ValidationResult> results,
            Instant startTime,
            Instant endTime,
            boolean fuzzingEnabled
        ) {
            this.results = Collections.unmodifiableList(new ArrayList<>(results));
            this.startTime = startTime;
            this.endTime = endTime;
            this.fuzzingEnabled = fuzzingEnabled;
            this.statistics = calculateStatistics();
        }

        private Map<String, Object> calculateStatistics() {
            Map<String, Object> stats = new HashMap<>();

            stats.put("totalEndpoints", results.size());
            stats.put("passed", results.stream()
                .filter(r -> r.getStatus() == ValidationResult.ValidationStatus.PASSED)
                .count());
            stats.put("failed", results.stream()
                .filter(r -> r.getStatus() == ValidationResult.ValidationStatus.FAILED)
                .count());
            stats.put("warnings", results.stream()
                .filter(r -> r.getStatus() == ValidationResult.ValidationStatus.WARNING)
                .count());
            stats.put("notDocumented", results.stream()
                .filter(r -> r.getStatus() == ValidationResult.ValidationStatus.NOT_DOCUMENTED)
                .count());

            long totalDivergences = results.stream()
                .mapToLong(r -> r.getDivergences().size())
                .sum();
            stats.put("totalDivergences", totalDivergences);

            long criticalCount = results.stream()
                .mapToLong(ValidationResult::getCriticalCount)
                .sum();
            stats.put("criticalDivergences", criticalCount);

            long highCount = results.stream()
                .mapToLong(ValidationResult::getHighCount)
                .sum();
            stats.put("highDivergences", highCount);

            long duration = java.time.Duration.between(startTime, endTime).toMillis();
            stats.put("durationMs", duration);

            return Collections.unmodifiableMap(stats);
        }

        public List<ValidationResult> getResults() {
            return results;
        }

        public Instant getStartTime() {
            return startTime;
        }

        public Instant getEndTime() {
            return endTime;
        }

        public boolean isFuzzingEnabled() {
            return fuzzingEnabled;
        }

        public Map<String, Object> getStatistics() {
            return statistics;
        }

        public int getTotalEndpoints() {
            return (int) statistics.get("totalEndpoints");
        }

        public long getTotalDivergences() {
            return (long) statistics.get("totalDivergences");
        }

        public long getCriticalDivergences() {
            return (long) statistics.get("criticalDivergences");
        }

        public long getHighDivergences() {
            return (long) statistics.get("highDivergences");
        }

        public boolean hasCriticalIssues() {
            return getCriticalDivergences() > 0;
        }

        public boolean hasDivergences() {
            return getTotalDivergences() > 0;
        }

        public boolean isValid() {
            return !hasCriticalIssues() && (long) statistics.get("failed") == 0;
        }

        /**
         * Get all divergences grouped by severity.
         */
        public Map<Divergence.Severity, List<Divergence>> getDivergencesBySeverity() {
            return results.stream()
                .flatMap(r -> r.getDivergences().stream())
                .collect(Collectors.groupingBy(Divergence::getSeverity));
        }

        /**
         * Get summary text report.
         */
        public String getSummary() {
            StringBuilder sb = new StringBuilder();
            sb.append("Contract Validation Report\n");
            sb.append("=========================\n\n");
            sb.append("Duration: ").append(statistics.get("durationMs")).append("ms\n");
            sb.append("Fuzzing: ").append(fuzzingEnabled ? "Enabled" : "Disabled").append("\n\n");
            sb.append("Endpoints:\n");
            sb.append("  Total: ").append(getTotalEndpoints()).append("\n");
            sb.append("  Passed: ").append(statistics.get("passed")).append("\n");
            sb.append("  Failed: ").append(statistics.get("failed")).append("\n");
            sb.append("  Warnings: ").append(statistics.get("warnings")).append("\n");
            sb.append("  Not Documented: ").append(statistics.get("notDocumented")).append("\n\n");
            sb.append("Divergences:\n");
            sb.append("  Total: ").append(getTotalDivergences()).append("\n");
            sb.append("  Critical: ").append(getCriticalDivergences()).append("\n");
            sb.append("  High: ").append(getHighDivergences()).append("\n\n");
            sb.append("Status: ").append(isValid() ? "✓ VALID" : "✗ INVALID").append("\n");

            return sb.toString();
        }

        @Override
        public String toString() {
            return getSummary();
        }
    }
}
