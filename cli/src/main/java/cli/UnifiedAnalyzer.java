package cli;

import active.ActiveAnalysisEngine;
import active.auth.AuthCredentials;
import active.auth.AuthenticationHelper;
import active.http.HttpClient;
import active.http.HttpClientConfig;
import active.http.HttpClientFactory;
import active.model.ApiEndpoint;
import active.scanner.ScanContext;
import active.validator.ContractValidationEngine;
import report.AnalysisReport;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.PathItem;
import model.ParameterSpec;
import model.ValidationFinding;
import parser.OpenApiLoader;
import parser.SpecNormalizer;
import validator.StaticContractValidator;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * Unified analyzer that coordinates both static and active analysis.
 */
public final class UnifiedAnalyzer {
    private static final Logger logger = Logger.getLogger(UnifiedAnalyzer.class.getName());

    private final OpenApiLoader loader;
    private final AnalyzerConfig config;

    public UnifiedAnalyzer(AnalyzerConfig config) {
        this.loader = new OpenApiLoader();
        this.config = config;
    }

    public UnifiedAnalyzer() {
        this(AnalyzerConfig.builder().build());
    }

    /**
     * Perform analysis based on the configured mode.
     *
     * @param specLocation path or URL to OpenAPI specification
     * @return unified analysis report
     */
    public AnalysisReport analyze(String specLocation) {
        Instant startTime = Instant.now();

        logger.info("Starting analysis in " + config.getMode() + " mode");

        AnalysisReport.Builder reportBuilder = AnalysisReport.builder()
            .specLocation(specLocation)
            .startTime(startTime)
            .mode(config.getMode());

        // Load specification
        OpenApiLoader.LoadResult loadResult;
        try {
            loadResult = loader.load(specLocation);
        } catch (Exception e) {
            logger.severe("Failed to load specification: " + e.getMessage());
            return reportBuilder
                .endTime(Instant.now())
                .staticResult(new AnalysisReport.StaticAnalysisResult(
                    List.of(), List.of(), "Failed to load specification: " + e.getMessage()))
                .build();
        }

        if (!loadResult.isSuccessful()) {
            String error = "Failed to parse OpenAPI specification";
            if (!loadResult.getMessages().isEmpty()) {
                error += ": " + String.join(", ", loadResult.getMessages());
            }
            return reportBuilder
                .endTime(Instant.now())
                .staticResult(new AnalysisReport.StaticAnalysisResult(
                    loadResult.getMessages(), List.of(), error))
                .build();
        }

        OpenAPI openAPI = loadResult.getOpenAPI();

        // Static analysis
        if (config.getMode() == AnalysisReport.AnalysisMode.STATIC_ONLY ||
            config.getMode() == AnalysisReport.AnalysisMode.COMBINED) {

            logger.info("Performing static analysis");
            AnalysisReport.StaticAnalysisResult staticResult = performStaticAnalysis(
                openAPI, loadResult.getMessages());
            reportBuilder.staticResult(staticResult);
        }

        // Active analysis
        if (config.getMode() == AnalysisReport.AnalysisMode.ACTIVE_ONLY ||
            config.getMode() == AnalysisReport.AnalysisMode.COMBINED) {

            // Determine base URL: use config override or extract from spec
            String baseUrl = determineBaseUrl(openAPI);

            if (baseUrl == null) {
                String error = "Active analysis requires a base URL. " +
                    "Provide --base-url parameter or define servers in OpenAPI spec";
                logger.warning(error);
                reportBuilder.activeResult(new AnalysisReport.ActiveAnalysisResult(null, error));
            } else {
                logger.info("Performing active analysis against: " + baseUrl);
                AnalysisReport.ActiveAnalysisResult activeResult = performActiveAnalysis(openAPI, baseUrl);
                reportBuilder.activeResult(activeResult);
            }
        }

        // Contract validation
        if (config.getMode() == AnalysisReport.AnalysisMode.CONTRACT) {
            String baseUrl = determineBaseUrl(openAPI);

            if (baseUrl == null) {
                String error = "Contract validation requires a base URL. " +
                    "Provide --base-url parameter or define servers in OpenAPI spec";
                logger.warning(error);
                reportBuilder.contractResult(new AnalysisReport.ContractAnalysisResult(null, error));
            } else {
                logger.info("Performing contract validation against: " + baseUrl);
                AnalysisReport.ContractAnalysisResult contractResult =
                    performContractValidation(openAPI, baseUrl);
                reportBuilder.contractResult(contractResult);
            }
        }

        reportBuilder.endTime(Instant.now());
        return reportBuilder.build();
    }

    private AnalysisReport.StaticAnalysisResult performStaticAnalysis(
            OpenAPI openAPI, List<String> parsingMessages) {
        try {
            StaticContractValidator validator = new StaticContractValidator(openAPI);
            List<ValidationFinding> findings = validator.validate();

            logger.info("Static analysis completed: " + findings.size() + " findings");
            return new AnalysisReport.StaticAnalysisResult(parsingMessages, findings, null);

        } catch (Exception e) {
            logger.severe("Static analysis failed: " + e.getMessage());
            return new AnalysisReport.StaticAnalysisResult(
                parsingMessages, List.of(), "Static analysis failed: " + e.getMessage());
        }
    }

    /**
     * Determine base URL for active analysis.
     * Priority: config override > first server in spec > null
     */
    private String determineBaseUrl(OpenAPI openAPI) {
        // First, check if user provided explicit override
        if (config.getBaseUrl() != null && !config.getBaseUrl().trim().isEmpty()) {
            logger.info("Using base URL from --base-url parameter: " + config.getBaseUrl());
            return config.getBaseUrl();
        }

        // Otherwise, try to extract from OpenAPI servers
        if (openAPI.getServers() != null && !openAPI.getServers().isEmpty()) {
            Server firstServer = openAPI.getServers().get(0);
            String url = firstServer.getUrl();

            if (url != null && !url.trim().isEmpty()) {
                logger.info("Using base URL from OpenAPI spec: " + url);

                // Log if there are multiple servers
                if (openAPI.getServers().size() > 1) {
                    logger.info("Note: Multiple servers defined in spec, using first one. " +
                        "Use --base-url to override");
                }

                return url;
            }
        }

        return null;
    }

    private AnalysisReport.ActiveAnalysisResult performActiveAnalysis(OpenAPI openAPI, String baseUrl) {
        ActiveAnalysisEngine engine = null;
        try {
            // Create and configure analysis engine
            ActiveAnalysisEngine.AnalysisConfig analysisConfig =
                ActiveAnalysisEngine.AnalysisConfig.builder()
                    .cryptoProtocol(config.getCryptoProtocol())
                    .verifySsl(config.isVerifySsl())
                    .maxParallelScans(config.getMaxParallelScans())
                    .build();

            engine = new ActiveAnalysisEngine(analysisConfig);
            // Scanners are auto-registered via ServiceLoader (see META-INF/services)

            // Extract endpoints from OpenAPI spec
            List<ApiEndpoint> endpoints = extractEndpoints(openAPI);
            logger.info("Extracted " + endpoints.size() + " endpoints for active scanning");

            if (endpoints.isEmpty()) {
                logger.warning("No endpoints found in specification");
                return new AnalysisReport.ActiveAnalysisResult(
                    null, "No endpoints found in specification");
            }

            // Create scan context
            ScanContext.Builder contextBuilder = ScanContext.builder()
                .baseUrl(baseUrl)
                .verbose(config.isVerbose());

            // Try automatic authentication if no auth header provided
            if (config.getAuthHeader() != null) {
                String[] parts = config.getAuthHeader().split(":", 2);
                if (parts.length == 2) {
                    contextBuilder.addAuthHeader(parts[0].trim(), parts[1].trim());
                    logger.info("Using provided authentication header");
                }
            } else if (config.isAutoAuth()) {
                logger.info("Attempting automatic authentication...");

                // Create temporary HTTP client for authentication
                HttpClientConfig authClientConfig = HttpClientConfig.builder()
                    .cryptoProtocol(config.getCryptoProtocol())
                    .verifySsl(config.isVerifySsl())
                    .build();
                HttpClient authHttpClient = HttpClientFactory.createClient(authClientConfig);

                AuthenticationHelper authHelper = new AuthenticationHelper(authHttpClient, baseUrl);

                // Try to authenticate
                Optional<AuthCredentials> primaryCreds = authHelper.attemptAutoAuth(endpoints);

                if (primaryCreds.isPresent()) {
                    AuthCredentials creds = primaryCreds.get();
                    String authHeader = creds.getAuthorizationHeader();
                    if (authHeader != null) {
                        contextBuilder.addAuthHeader("Authorization", authHeader);
                        logger.info("✓ Auto-authentication successful for user: " + creds.getUsername());
                    }

                    // Store primary credentials in shared data
                    contextBuilder.sharedData(Map.of("primaryCredentials", creds));

                    // Create additional test users for BOLA testing
                    if (config.isCreateTestUsers()) {
                        logger.info("Creating additional test users for BOLA testing...");
                        List<AuthCredentials> testUsers = authHelper.createTestUsers(endpoints, 2);
                        if (!testUsers.isEmpty()) {
                            contextBuilder.sharedData(Map.of(
                                "primaryCredentials", creds,
                                "testUsers", testUsers
                            ));
                            logger.info("✓ Created " + testUsers.size() + " additional test users");
                        }
                    }
                } else {
                    logger.warning("⚠ Auto-authentication failed. Protected endpoints may not be testable.");
                    logger.info("  Tip: Provide authentication via --auth-header or ensure API has registration endpoint");
                }
            }

            ScanContext context = contextBuilder.build();

            // Execute scan
            ActiveAnalysisEngine.AnalysisReport activeReport = engine.scanEndpoints(endpoints, context);

            logger.info("Active analysis completed: " +
                activeReport.getTotalVulnerabilityCount() + " vulnerabilities found");

            return new AnalysisReport.ActiveAnalysisResult(activeReport, null);

        } catch (Exception e) {
            logger.severe("Active analysis failed: " + e.getMessage());
            return new AnalysisReport.ActiveAnalysisResult(
                null, "Active analysis failed: " + e.getMessage());
        } finally {
            if (engine != null) {
                engine.shutdown();
            }
        }
    }

    private AnalysisReport.ContractAnalysisResult performContractValidation(OpenAPI openAPI, String baseUrl) {
        try {
            // Create contract validation engine
            boolean fuzzingEnabled = !config.isNoFuzzing();
            ContractValidationEngine engine = new ContractValidationEngine(openAPI, baseUrl, fuzzingEnabled);

            // Extract endpoints from OpenAPI spec
            List<ApiEndpoint> endpoints = extractEndpoints(openAPI);
            logger.info("Extracted " + endpoints.size() + " endpoints for contract validation");

            if (endpoints.isEmpty()) {
                logger.warning("No endpoints found in specification");
                return new AnalysisReport.ContractAnalysisResult(
                    null, "No endpoints found in specification");
            }

            // Create HTTP client
            HttpClientConfig clientConfig = HttpClientConfig.builder()
                .cryptoProtocol(config.getCryptoProtocol())
                .verifySsl(config.isVerifySsl())
                .build();
            HttpClient httpClient = HttpClientFactory.createClient(clientConfig);

            // Run contract validation
            ContractValidationEngine.ContractValidationReport report =
                engine.validate(endpoints, httpClient);

            logger.info("Contract validation completed: " +
                report.getTotalDivergences() + " divergences found");

            return new AnalysisReport.ContractAnalysisResult(report, null);

        } catch (Exception e) {
            logger.severe("Contract validation failed: " + e.getMessage());
            return new AnalysisReport.ContractAnalysisResult(
                null, "Contract validation failed: " + e.getMessage());
        }
    }

    /**
     * Extract API endpoints from OpenAPI specification.
     */
    private List<ApiEndpoint> extractEndpoints(OpenAPI openAPI) {
        List<ApiEndpoint> endpoints = new ArrayList<>();

        if (openAPI.getPaths() == null) {
            return endpoints;
        }

        SpecNormalizer normalizer = new SpecNormalizer();
        var operations = normalizer.normalize(openAPI);

        for (var op : operations) {
            // Convert parameters
            List<ParameterSpec> params = op.getParameters().stream()
                .map(param -> ParameterSpec.builder()
                    .name(param.getName())
                    .location(param.getLocation())
                    .required(param.isRequired())
                    .build())
                .toList();

            ApiEndpoint.Builder endpointBuilder = ApiEndpoint.builder()
                .path(op.getPath())
                .method(op.getMethod())
                .operationId(op.getOperationId())
                .parameters(params);

            // Include request body schema if present
            if (op.getRequestBodySchema().isPresent()) {
                endpointBuilder.addMetadata("requestBodySchema", op.getRequestBodySchema().get());
            }

            // Include security schemes
            if (!op.getSecuritySchemes().isEmpty()) {
                endpointBuilder.securitySchemes(op.getSecuritySchemes());
            }

            // Include summary and description
            if (op.getSummary() != null) {
                endpointBuilder.addMetadata("summary", op.getSummary());
            }

            endpoints.add(endpointBuilder.build());
        }

        return endpoints;
    }

    /**
     * Configuration for the unified analyzer.
     */
    public static final class AnalyzerConfig {
        private final AnalysisReport.AnalysisMode mode;
        private final String baseUrl;
        private final String authHeader;
        private final HttpClient.CryptoProtocol cryptoProtocol;
        private final boolean verifySsl;
        private final int maxParallelScans;
        private final boolean verbose;
        private final boolean autoAuth;
        private final boolean createTestUsers;
        private final boolean noFuzzing;

        private AnalyzerConfig(Builder builder) {
            this.mode = builder.mode != null ? builder.mode : AnalysisReport.AnalysisMode.STATIC_ONLY;
            this.baseUrl = builder.baseUrl;
            this.authHeader = builder.authHeader;
            this.cryptoProtocol = builder.cryptoProtocol != null
                ? builder.cryptoProtocol
                : HttpClient.CryptoProtocol.STANDARD_TLS;
            this.verifySsl = builder.verifySsl;
            this.maxParallelScans = builder.maxParallelScans > 0 ? builder.maxParallelScans : 4;
            this.verbose = builder.verbose;
            this.autoAuth = builder.autoAuth;
            this.createTestUsers = builder.createTestUsers;
            this.noFuzzing = builder.noFuzzing;
        }

        public static Builder builder() {
            return new Builder();
        }

        public AnalysisReport.AnalysisMode getMode() {
            return mode;
        }

        public String getBaseUrl() {
            return baseUrl;
        }

        public String getAuthHeader() {
            return authHeader;
        }

        public HttpClient.CryptoProtocol getCryptoProtocol() {
            return cryptoProtocol;
        }

        public boolean isVerifySsl() {
            return verifySsl;
        }

        public int getMaxParallelScans() {
            return maxParallelScans;
        }

        public boolean isVerbose() {
            return verbose;
        }

        public boolean isAutoAuth() {
            return autoAuth;
        }

        public boolean isCreateTestUsers() {
            return createTestUsers;
        }

        public boolean isNoFuzzing() {
            return noFuzzing;
        }

        public static class Builder {
            private AnalysisReport.AnalysisMode mode;
            private String baseUrl;
            private String authHeader;
            private HttpClient.CryptoProtocol cryptoProtocol;
            private boolean verifySsl = true;
            private int maxParallelScans = 4;
            private boolean verbose = false;
            private boolean autoAuth = true; // Enabled by default
            private boolean createTestUsers = true; // Enabled by default
            private boolean noFuzzing = false;

            public Builder mode(AnalysisReport.AnalysisMode mode) {
                this.mode = mode;
                return this;
            }

            public Builder baseUrl(String baseUrl) {
                this.baseUrl = baseUrl;
                return this;
            }

            public Builder authHeader(String authHeader) {
                this.authHeader = authHeader;
                return this;
            }

            public Builder cryptoProtocol(HttpClient.CryptoProtocol cryptoProtocol) {
                this.cryptoProtocol = cryptoProtocol;
                return this;
            }

            public Builder verifySsl(boolean verifySsl) {
                this.verifySsl = verifySsl;
                return this;
            }

            public Builder maxParallelScans(int maxParallelScans) {
                this.maxParallelScans = maxParallelScans;
                return this;
            }

            public Builder verbose(boolean verbose) {
                this.verbose = verbose;
                return this;
            }

            public Builder autoAuth(boolean autoAuth) {
                this.autoAuth = autoAuth;
                return this;
            }

            public Builder createTestUsers(boolean createTestUsers) {
                this.createTestUsers = createTestUsers;
                return this;
            }

            public Builder noFuzzing(boolean noFuzzing) {
                this.noFuzzing = noFuzzing;
                return this;
            }

            public AnalyzerConfig build() {
                return new AnalyzerConfig(this);
            }
        }
    }
}
