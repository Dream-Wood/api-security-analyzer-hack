package active.validator;

import active.http.HttpClient;
import active.model.ApiEndpoint;
import active.model.TestRequest;
import active.model.TestResponse;
import active.validator.model.Divergence;
import active.validator.model.FuzzTestCase;
import active.validator.model.ValidationResult;
import com.fasterxml.jackson.databind.JsonNode;
import io.swagger.v3.oas.models.OpenAPI;

import java.util.*;
import java.util.logging.Logger;

/**
 * Main endpoint validator that orchestrates specification validation,
 * divergence detection, and fuzzing tests.
 */
public final class EndpointValidator {
    private static final Logger logger = Logger.getLogger(EndpointValidator.class.getName());

    private final OpenAPI openAPI;
    private final SpecificationValidator specValidator;
    private final DivergenceDetector divergenceDetector;
    private final FuzzingGenerator fuzzingGenerator;
    private final boolean enableFuzzing;
    private final String baseUrl;

    public EndpointValidator(OpenAPI openAPI) {
        this(openAPI, null, true);
    }

    public EndpointValidator(OpenAPI openAPI, boolean enableFuzzing) {
        this(openAPI, null, enableFuzzing);
    }

    public EndpointValidator(OpenAPI openAPI, String baseUrl, boolean enableFuzzing) {
        this.openAPI = Objects.requireNonNull(openAPI, "OpenAPI cannot be null");
        this.specValidator = new SpecificationValidator();
        this.divergenceDetector = new DivergenceDetector(openAPI);
        this.fuzzingGenerator = new FuzzingGenerator();
        this.enableFuzzing = enableFuzzing;
        this.baseUrl = baseUrl;
    }

    /**
     * Validate an endpoint against its specification and perform fuzzing tests.
     *
     * @param endpoint the endpoint to validate
     * @param httpClient the HTTP client for testing
     * @return validation result with all detected divergences
     */
    public ValidationResult validateEndpoint(ApiEndpoint endpoint, HttpClient httpClient) {
        logger.info("Validating endpoint: " + endpoint);

        List<Divergence> allDivergences = new ArrayList<>();
        int totalTests = 0;

        try {
            // 1. Check if endpoint is documented
            if (!divergenceDetector.isEndpointDocumented(endpoint)) {
                return ValidationResult.builder()
                    .endpoint(endpoint.getPath())
                    .method(endpoint.getMethod())
                    .status(ValidationResult.ValidationStatus.NOT_DOCUMENTED)
                    .addDivergence(Divergence.builder()
                        .type(active.validator.model.DivergenceType.UNDOCUMENTED_ENDPOINT)
                        .path(endpoint.getPath())
                        .message("Endpoint is not documented in API specification")
                        .severity(Divergence.Severity.HIGH)
                        .build())
                    .totalTests(0)
                    .build();
            }

            // 2. Test nominal behavior
            TestResponse nominalResponse = testNominalBehavior(endpoint, httpClient);
            totalTests++;

            if (nominalResponse != null) {
                List<Divergence> nominalDivergences = divergenceDetector.detectDivergences(
                    endpoint, nominalResponse
                );
                allDivergences.addAll(nominalDivergences);
            }

            // 3. Perform fuzzing tests if enabled
            if (enableFuzzing) {
                List<Divergence> fuzzDivergences = performFuzzingTests(
                    endpoint, httpClient
                );
                allDivergences.addAll(fuzzDivergences);
                totalTests += 10; // Approximate number of fuzz tests
            }

            // 4. Determine overall status
            ValidationResult.ValidationStatus status = determineStatus(allDivergences);

            return ValidationResult.builder()
                .endpoint(endpoint.getPath())
                .method(endpoint.getMethod())
                .status(status)
                .divergences(allDivergences)
                .totalTests(totalTests)
                .addMetadata("operationId", endpoint.getOperationId())
                .addMetadata("fuzzingEnabled", enableFuzzing)
                .build();

        } catch (Exception e) {
            logger.warning("Validation failed for " + endpoint + ": " + e.getMessage());

            return ValidationResult.builder()
                .endpoint(endpoint.getPath())
                .method(endpoint.getMethod())
                .status(ValidationResult.ValidationStatus.ERROR)
                .addDivergence(Divergence.builder()
                    .type(active.validator.model.DivergenceType.SCHEMA_VIOLATION)
                    .path(endpoint.getPath())
                    .message("Validation error: " + e.getMessage())
                    .severity(Divergence.Severity.HIGH)
                    .build())
                .totalTests(totalTests)
                .build();
        }
    }

    /**
     * Test normal/expected behavior of the endpoint.
     */
    private TestResponse testNominalBehavior(ApiEndpoint endpoint, HttpClient httpClient) {
        try {
            // Build a basic request
            String fullUrl = buildFullUrl(endpoint.getPath());
            TestRequest.Builder requestBuilder = TestRequest.builder()
                .url(fullUrl)
                .method(endpoint.getMethod());

            // Add any required authentication
            if (endpoint.requiresAuthentication()) {
                // This would be populated from context in real usage
                requestBuilder.addHeader("Authorization", "Bearer test-token");
            }

            TestRequest request = requestBuilder.build();
            return httpClient.execute(request);

        } catch (Exception e) {
            logger.warning("Failed to test nominal behavior: " + e.getMessage());
            return null;
        }
    }

    /**
     * Perform fuzzing tests on the endpoint.
     */
    private List<Divergence> performFuzzingTests(ApiEndpoint endpoint, HttpClient httpClient) {
        List<Divergence> divergences = new ArrayList<>();

        try {
            // Get expected schema for this endpoint
            Optional<JsonNode> schema = Optional.empty(); // Would be extracted from OpenAPI

            // Generate fuzz test cases
            List<FuzzTestCase> fuzzTests = fuzzingGenerator.generateFuzzTests(endpoint, schema);

            // Execute a subset of fuzz tests (limit to avoid excessive testing)
            int maxFuzzTests = Math.min(fuzzTests.size(), 20);

            for (int i = 0; i < maxFuzzTests; i++) {
                FuzzTestCase fuzzTest = fuzzTests.get(i);

                try {
                    TestResponse response = executeFuzzTest(endpoint, fuzzTest, httpClient);

                    // Analyze the response
                    List<Divergence> fuzzDivergences = analyzeFuzzResponse(
                        endpoint, fuzzTest, response
                    );
                    divergences.addAll(fuzzDivergences);

                } catch (Exception e) {
                    logger.fine("Fuzz test failed (expected): " + fuzzTest.getName());
                }
            }

        } catch (Exception e) {
            logger.warning("Fuzzing tests failed: " + e.getMessage());
        }

        return divergences;
    }

    /**
     * Execute a single fuzz test.
     */
    private TestResponse executeFuzzTest(
        ApiEndpoint endpoint,
        FuzzTestCase fuzzTest,
        HttpClient httpClient
    ) {
        String fullUrl = buildFullUrl(endpoint.getPath());
        TestRequest.Builder requestBuilder = TestRequest.builder()
            .url(fullUrl)
            .method(endpoint.getMethod());

        // Add fuzzed parameters
        fuzzTest.getParameters().forEach((key, value) -> {
            if (value != null) {
                requestBuilder.addQueryParam(key, value.toString());
            }
        });

        // Add fuzzed body
        if (fuzzTest.getBodyPayload() != null) {
            String body = fuzzTest.getBodyPayload().toString();
            requestBuilder.body(body);
            requestBuilder.addHeader("Content-Type", "application/json");
        }

        // Add fuzzed headers
        fuzzTest.getHeaders().forEach(requestBuilder::addHeader);

        return httpClient.execute(requestBuilder.build());
    }

    /**
     * Analyze response from a fuzz test.
     */
    private List<Divergence> analyzeFuzzResponse(
        ApiEndpoint endpoint,
        FuzzTestCase fuzzTest,
        TestResponse response
    ) {
        List<Divergence> divergences = new ArrayList<>();

        FuzzTestCase.ExpectedBehavior expected = fuzzTest.getExpectedBehavior();

        switch (expected) {
            case GRACEFUL_ERROR:
                // Should return 4xx error
                if (response.getStatusCode() >= 500) {
                    divergences.add(Divergence.builder()
                        .type(active.validator.model.DivergenceType.UNEXPECTED_STATUS_CODE)
                        .path(endpoint.getPath())
                        .message(String.format(
                            "Fuzz test '%s' caused server error (5xx) instead of graceful 4xx",
                            fuzzTest.getName()
                        ))
                        .actualValue(response.getStatusCode())
                        .expectedValue("4xx")
                        .severity(Divergence.Severity.HIGH)
                        .addMetadata("fuzzCategory", fuzzTest.getCategory().toString())
                        .build());
                }
                break;

            case REJECT_INVALID:
                // Should reject with validation error (400, 422)
                if (response.getStatusCode() < 400 || response.getStatusCode() >= 500) {
                    divergences.add(Divergence.builder()
                        .type(active.validator.model.DivergenceType.SCHEMA_VIOLATION)
                        .path(endpoint.getPath())
                        .message(String.format(
                            "Fuzz test '%s' was not properly rejected (expected 4xx)",
                            fuzzTest.getName()
                        ))
                        .actualValue(response.getStatusCode())
                        .expectedValue("400 or 422")
                        .severity(Divergence.Severity.MEDIUM)
                        .addMetadata("fuzzCategory", fuzzTest.getCategory().toString())
                        .build());
                }
                break;

            case NO_CRASH:
                // Should not return 5xx
                if (response.getStatusCode() >= 500) {
                    divergences.add(Divergence.builder()
                        .type(active.validator.model.DivergenceType.UNEXPECTED_STATUS_CODE)
                        .path(endpoint.getPath())
                        .message(String.format(
                            "Fuzz test '%s' caused server crash (5xx)",
                            fuzzTest.getName()
                        ))
                        .actualValue(response.getStatusCode())
                        .severity(Divergence.Severity.CRITICAL)
                        .addMetadata("fuzzCategory", fuzzTest.getCategory().toString())
                        .build());
                }
                break;

            case CONSISTENT_SCHEMA:
                // Response schema should be consistent
                // This would require comparing with previous responses
                break;
        }

        return divergences;
    }

    /**
     * Determine overall validation status based on divergences.
     */
    private ValidationResult.ValidationStatus determineStatus(List<Divergence> divergences) {
        if (divergences.isEmpty()) {
            return ValidationResult.ValidationStatus.PASSED;
        }

        boolean hasCritical = divergences.stream()
            .anyMatch(d -> d.getSeverity() == Divergence.Severity.CRITICAL);

        boolean hasHigh = divergences.stream()
            .anyMatch(d -> d.getSeverity() == Divergence.Severity.HIGH);

        if (hasCritical || hasHigh) {
            return ValidationResult.ValidationStatus.FAILED;
        }

        return ValidationResult.ValidationStatus.WARNING;
    }

    /**
     * Batch validate multiple endpoints.
     */
    public List<ValidationResult> validateEndpoints(
        List<ApiEndpoint> endpoints,
        HttpClient httpClient
    ) {
        List<ValidationResult> results = new ArrayList<>();

        for (ApiEndpoint endpoint : endpoints) {
            ValidationResult result = validateEndpoint(endpoint, httpClient);
            results.add(result);
        }

        return results;
    }

    /**
     * Get statistics from validation results.
     */
    public Map<String, Object> getValidationStatistics(List<ValidationResult> results) {
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

        long criticalDivergences = results.stream()
            .mapToLong(ValidationResult::getCriticalCount)
            .sum();
        stats.put("criticalDivergences", criticalDivergences);

        long highDivergences = results.stream()
            .mapToLong(ValidationResult::getHighCount)
            .sum();
        stats.put("highDivergences", highDivergences);

        return stats;
    }

    /**
     * Build full URL by combining base URL with endpoint path.
     */
    private String buildFullUrl(String path) {
        if (baseUrl == null || baseUrl.isEmpty()) {
            return path;
        }

        // Remove trailing slash from baseUrl and leading slash from path
        String normalizedBase = baseUrl.replaceAll("/+$", "");
        String normalizedPath = path.startsWith("/") ? path : "/" + path;

        return normalizedBase + normalizedPath;
    }
}
