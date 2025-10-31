package active;

import active.http.HttpClient;
import active.http.HttpClientConfig;
import active.http.HttpClientFactory;
import active.model.ApiEndpoint;
import active.model.VulnerabilityReport;
import active.scanner.*;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Main orchestrator for active API security analysis.
 * This engine coordinates vulnerability scanners, HTTP clients, and reporting.
 */
public final class ActiveAnalysisEngine {
    private static final Logger logger = Logger.getLogger(ActiveAnalysisEngine.class.getName());

    private final HttpClient httpClient;
    private final ScannerRegistry scannerRegistry;
    private final AnalysisConfig analysisConfig;
    private final ExecutorService executorService;

    public ActiveAnalysisEngine(AnalysisConfig analysisConfig) {
        this.analysisConfig = analysisConfig;

        // Create HTTP client based on config
        HttpClientConfig httpConfig = HttpClientConfig.builder()
            .cryptoProtocol(analysisConfig.getCryptoProtocol())
            .connectTimeout(Duration.ofSeconds(30))
            .readTimeout(Duration.ofSeconds(30))
            .followRedirects(true)
            .verifySsl(analysisConfig.isVerifySsl())
            .build();

        this.httpClient = HttpClientFactory.createClient(httpConfig);
        this.scannerRegistry = new ScannerRegistry();

        // Auto-discover and register scanners using ServiceLoader
        int scannersRegistered = ScannerAutoDiscovery.discoverAndRegister(scannerRegistry);
        logger.info("Auto-registered " + scannersRegistered + " scanner(s) via ServiceLoader");

        // Create thread pool for parallel scanning
        this.executorService = Executors.newFixedThreadPool(
            analysisConfig.getMaxParallelScans()
        );

        logger.info("Active Analysis Engine initialized with crypto protocol: " +
                   analysisConfig.getCryptoProtocol().getDisplayName());
    }

    /**
     * Register a vulnerability scanner.
     */
    public void registerScanner(VulnerabilityScanner scanner) {
        scannerRegistry.register(scanner);
    }

    /**
     * Scan a single endpoint with all applicable scanners.
     */
    public EndpointAnalysisResult scanEndpoint(ApiEndpoint endpoint, ScanContext context) {
        Instant startTime = Instant.now();
        logger.info("Scanning endpoint: " + endpoint);

        List<VulnerabilityScanner> applicableScanners = scannerRegistry.getEnabledScanners()
            .stream()
            .filter(scanner -> scanner.isApplicable(endpoint))
            .toList();

        if (applicableScanners.isEmpty()) {
            logger.fine("No applicable scanners for endpoint: " + endpoint);
            return new EndpointAnalysisResult(
                endpoint,
                Collections.emptyList(),
                startTime,
                Instant.now()
            );
        }

        logger.info("Running " + applicableScanners.size() + " scanner(s) on: " + endpoint);

        List<ScanResult> scanResults = new ArrayList<>();

        for (VulnerabilityScanner scanner : applicableScanners) {
            try {
                ScanResult result = scanner.scan(endpoint, httpClient, context);
                scanResults.add(result);

                if (result.hasVulnerabilities()) {
                    logger.warning("Found " + result.getVulnerabilityCount() +
                                 " vulnerabilities with " + scanner.getName());
                }
            } catch (Exception e) {
                logger.warning("Scanner " + scanner.getName() + " failed: " + e.getMessage());
            }
        }

        return new EndpointAnalysisResult(
            endpoint,
            scanResults,
            startTime,
            Instant.now()
        );
    }

    /**
     * Scan multiple endpoints in parallel.
     */
    public AnalysisReport scanEndpoints(List<ApiEndpoint> endpoints, ScanContext context) {
        Instant startTime = Instant.now();
        logger.info("Starting active analysis of " + endpoints.size() + " endpoints");

        List<Future<EndpointAnalysisResult>> futures = endpoints.stream()
            .map(endpoint -> executorService.submit(() -> scanEndpoint(endpoint, context)))
            .toList();

        List<EndpointAnalysisResult> results = new ArrayList<>();
        for (Future<EndpointAnalysisResult> future : futures) {
            try {
                results.add(future.get());
            } catch (Exception e) {
                logger.warning("Endpoint scan failed: " + e.getMessage());
            }
        }

        Instant endTime = Instant.now();
        logger.info("Active analysis completed in " + Duration.between(startTime, endTime).toSeconds() + "s");

        return new AnalysisReport(results, startTime, endTime);
    }

    /**
     * Get the scanner registry.
     */
    public ScannerRegistry getScannerRegistry() {
        return scannerRegistry;
    }

    /**
     * Shutdown the engine and release resources.
     */
    public void shutdown() {
        logger.info("Shutting down Active Analysis Engine");

        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(60, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }

        httpClient.close();
    }

    /**
     * Configuration for the active analysis engine.
     */
    public static final class AnalysisConfig {
        private final HttpClient.CryptoProtocol cryptoProtocol;
        private final boolean verifySsl;
        private final int maxParallelScans;

        private AnalysisConfig(Builder builder) {
            this.cryptoProtocol = builder.cryptoProtocol != null
                ? builder.cryptoProtocol
                : HttpClient.CryptoProtocol.STANDARD_TLS;
            this.verifySsl = builder.verifySsl;
            this.maxParallelScans = builder.maxParallelScans > 0
                ? builder.maxParallelScans
                : Runtime.getRuntime().availableProcessors();
        }

        public static Builder builder() {
            return new Builder();
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

        public static class Builder {
            private HttpClient.CryptoProtocol cryptoProtocol;
            private boolean verifySsl = true;
            private int maxParallelScans = 4;

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

            public AnalysisConfig build() {
                return new AnalysisConfig(this);
            }
        }
    }

    /**
     * Result of analyzing a single endpoint.
     */
    public record EndpointAnalysisResult(
        ApiEndpoint endpoint,
        List<ScanResult> scanResults,
        Instant startTime,
        Instant endTime
    ) {
        public List<VulnerabilityReport> getAllVulnerabilities() {
            return scanResults.stream()
                .flatMap(result -> result.getVulnerabilities().stream())
                .toList();
        }

        public int getVulnerabilityCount() {
            return getAllVulnerabilities().size();
        }

        public Duration getDuration() {
            return Duration.between(startTime, endTime);
        }
    }

    /**
     * Complete analysis report for all scanned endpoints.
     */
    public static final class AnalysisReport {
        private final List<EndpointAnalysisResult> endpointResults;
        private final Instant startTime;
        private final Instant endTime;

        public AnalysisReport(List<EndpointAnalysisResult> endpointResults,
                             Instant startTime, Instant endTime) {
            this.endpointResults = Collections.unmodifiableList(new ArrayList<>(endpointResults));
            this.startTime = startTime;
            this.endTime = endTime;
        }

        public List<EndpointAnalysisResult> getEndpointResults() {
            return endpointResults;
        }

        public List<VulnerabilityReport> getAllVulnerabilities() {
            return endpointResults.stream()
                .flatMap(result -> result.getAllVulnerabilities().stream())
                .toList();
        }

        public int getTotalVulnerabilityCount() {
            return getAllVulnerabilities().size();
        }

        public int getEndpointCount() {
            return endpointResults.size();
        }

        public int getVulnerableEndpointCount() {
            return (int) endpointResults.stream()
                .filter(result -> result.getVulnerabilityCount() > 0)
                .count();
        }

        public Map<VulnerabilityReport.VulnerabilityType, Long> getVulnerabilityCountByType() {
            return getAllVulnerabilities().stream()
                .collect(Collectors.groupingBy(
                    VulnerabilityReport::getType,
                    Collectors.counting()
                ));
        }

        public Map<model.Severity, Long> getVulnerabilityCountBySeverity() {
            return getAllVulnerabilities().stream()
                .collect(Collectors.groupingBy(
                    VulnerabilityReport::getSeverity,
                    Collectors.counting()
                ));
        }

        public Duration getTotalDuration() {
            return Duration.between(startTime, endTime);
        }

        public Instant getStartTime() {
            return startTime;
        }

        public Instant getEndTime() {
            return endTime;
        }

        @Override
        public String toString() {
            return "AnalysisReport{" +
                   "endpoints=" + getEndpointCount() +
                   ", vulnerableEndpoints=" + getVulnerableEndpointCount() +
                   ", totalVulnerabilities=" + getTotalVulnerabilityCount() +
                   ", duration=" + getTotalDuration().toSeconds() + "s" +
                   '}';
        }
    }
}
