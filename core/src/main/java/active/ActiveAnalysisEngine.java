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
 * Главный оркестратор для активного анализа безопасности API.
 * Этот движок координирует работу сканеров уязвимостей, HTTP-клиентов и формирование отчетов.
 *
 * <p>Основные возможности:
 * <ul>
 *   <li>Автоматическое обнаружение и регистрация сканеров через ServiceLoader</li>
 *   <li>Поддержка различных криптографических протоколов (TLS, CryptoPro GOST)</li>
 *   <li>Параллельное сканирование эндпоинтов с настраиваемой интенсивностью</li>
 *   <li>Отслеживание прогресса сканирования через ScanProgressListener</li>
 *   <li>Гибкая конфигурация сканеров и задержек между запросами</li>
 * </ul>
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
        HttpClientConfig.Builder httpConfigBuilder = HttpClientConfig.builder()
            .cryptoProtocol(analysisConfig.getCryptoProtocol())
            .connectTimeout(Duration.ofSeconds(30))
            .readTimeout(Duration.ofSeconds(30))
            .followRedirects(true)
            .verifySsl(analysisConfig.isVerifySsl());

        // Add GOST configuration if provided
        if (analysisConfig.getGostPfxPath() != null) {
            httpConfigBuilder.addCustomSetting("pfxPath", analysisConfig.getGostPfxPath());
        }
        if (analysisConfig.getGostPfxPassword() != null) {
            httpConfigBuilder.addCustomSetting("pfxPassword", analysisConfig.getGostPfxPassword());
        }
        if (analysisConfig.isGostPfxResource()) {
            httpConfigBuilder.addCustomSetting("pfxResource", "true");
        }

        HttpClientConfig httpConfig = httpConfigBuilder.build();
        this.httpClient = HttpClientFactory.createClient(httpConfig);
        this.scannerRegistry = new ScannerRegistry();

        // Auto-discover and register scanners using ServiceLoader
        int scannersRegistered = ScannerAutoDiscovery.discoverAndRegister(scannerRegistry);
        logger.info("Auto-registered " + scannersRegistered + " scanner(s) via ServiceLoader");

        // Configure scanner enabled/disabled status and scan intensity
        ScanIntensity intensity = analysisConfig.getScanIntensity() != null
            ? ScanIntensity.fromString(analysisConfig.getScanIntensity())
            : ScanIntensity.MEDIUM;

        logger.info("Scan intensity: " + intensity + " (delay: " + intensity.getRequestDelayMs() + "ms)");

        if (analysisConfig.getEnabledScanners() != null && !analysisConfig.getEnabledScanners().isEmpty()) {
            Set<String> enabledSet = new HashSet<>(analysisConfig.getEnabledScanners());
            for (VulnerabilityScanner scanner : scannerRegistry.getAllScanners()) {
                boolean shouldEnable = enabledSet.contains(scanner.getId());
                ScannerConfig.Builder configBuilder = ScannerConfig.builder()
                    .enabled(shouldEnable)
                    .maxTestsPerEndpoint(scanner.getConfig().getMaxTestsPerEndpoint())
                    .timeoutSeconds(scanner.getConfig().getTimeoutSeconds())
                    .intensity(intensity);

                // Apply custom request delay if provided (overrides intensity default)
                if (analysisConfig.getRequestDelayMs() != null) {
                    configBuilder.requestDelayMs(analysisConfig.getRequestDelayMs());
                }

                scanner.setConfig(configBuilder.build());
            }
            logger.info("Configured scanner selection: " + enabledSet.size() + " enabled out of " + scannersRegistered);
        } else {
            // Apply intensity to all scanners
            for (VulnerabilityScanner scanner : scannerRegistry.getAllScanners()) {
                ScannerConfig.Builder configBuilder = ScannerConfig.builder()
                    .enabled(true)
                    .maxTestsPerEndpoint(scanner.getConfig().getMaxTestsPerEndpoint())
                    .timeoutSeconds(scanner.getConfig().getTimeoutSeconds())
                    .intensity(intensity);

                // Apply custom request delay if provided (overrides intensity default)
                if (analysisConfig.getRequestDelayMs() != null) {
                    configBuilder.requestDelayMs(analysisConfig.getRequestDelayMs());
                }

                scanner.setConfig(configBuilder.build());
            }
            logger.info("All scanners enabled by default");
        }

        // Create thread pool for parallel scanning
        this.executorService = Executors.newFixedThreadPool(
            analysisConfig.getMaxParallelScans()
        );

        logger.info("Active Analysis Engine initialized with crypto protocol: " +
                   analysisConfig.getCryptoProtocol().getDisplayName());
    }

    /**
     * Регистрирует сканер уязвимостей в реестре.
     *
     * @param scanner сканер уязвимостей для регистрации
     */
    public void registerScanner(VulnerabilityScanner scanner) {
        scannerRegistry.register(scanner);
    }

    /**
     * Сканирует один эндпоинт всеми применимыми сканерами.
     * Вспомогательный метод для последовательного сканирования с отслеживанием прогресса.
     *
     * @param endpoint эндпоинт для сканирования
     * @param context контекст сканирования
     * @param endpointIndex индекс текущего эндпоинта
     * @param totalEndpoints общее количество эндпоинтов
     * @param totalVulns счетчик общего количества найденных уязвимостей
     * @return результат анализа эндпоинта
     */
    private EndpointAnalysisResult scanEndpointWithProgress(
            ApiEndpoint endpoint,
            ScanContext context,
            int endpointIndex,
            int totalEndpoints,
            java.util.concurrent.atomic.AtomicInteger totalVulns) {

        Instant startTime = Instant.now();
        logger.info("Scanning endpoint: " + endpoint);

        // Notify start of endpoint scan
        analysisConfig.getProgressListener().onEndpointStart(
            endpointIndex, totalEndpoints, endpoint.toString());

        List<VulnerabilityScanner> applicableScanners = scannerRegistry.getEnabledScanners()
            .stream()
            .filter(scanner -> scanner.isApplicable(endpoint))
            .toList();

        if (applicableScanners.isEmpty()) {
            logger.fine("No applicable scanners for endpoint: " + endpoint);
            analysisConfig.getProgressListener().onEndpointComplete(
                endpointIndex, totalEndpoints, totalVulns.get());
            return new EndpointAnalysisResult(
                endpoint,
                Collections.emptyList(),
                startTime,
                Instant.now()
            );
        }

        logger.info("Running " + applicableScanners.size() + " scanner(s) on: " + endpoint);

        List<ScanResult> scanResults = new ArrayList<>();
        int scannerIndex = 0;

        for (VulnerabilityScanner scanner : applicableScanners) {
            try {
                // Notify scanner start
                analysisConfig.getProgressListener().onScannerStart(
                    scanner.getName(), scannerIndex, applicableScanners.size());

                ScanResult result = scanner.scan(endpoint, httpClient, context);
                scanResults.add(result);

                int vulnCount = result.getVulnerabilityCount();
                if (vulnCount > 0) {
                    totalVulns.addAndGet(vulnCount);
                    logger.warning("Found " + vulnCount +
                                 " vulnerabilities with " + scanner.getName());
                }

                // Notify scanner complete
                analysisConfig.getProgressListener().onScannerComplete(
                    scanner.getName(), vulnCount);

            } catch (Exception e) {
                logger.warning("Scanner " + scanner.getName() + " failed: " + e.getMessage());
                analysisConfig.getProgressListener().onScannerComplete(scanner.getName(), 0);
            }
            scannerIndex++;
        }

        // Notify endpoint complete
        analysisConfig.getProgressListener().onEndpointComplete(
            endpointIndex, totalEndpoints, totalVulns.get());

        return new EndpointAnalysisResult(
            endpoint,
            scanResults,
            startTime,
            Instant.now()
        );
    }

    /**
     * Сканирует один эндпоинт всеми применимыми сканерами.
     *
     * @param endpoint эндпоинт для сканирования
     * @param context контекст сканирования
     * @return результат анализа эндпоинта
     */
    public EndpointAnalysisResult scanEndpoint(ApiEndpoint endpoint, ScanContext context) {
        java.util.concurrent.atomic.AtomicInteger totalVulns = new java.util.concurrent.atomic.AtomicInteger(0);
        return scanEndpointWithProgress(endpoint, context, 0, 1, totalVulns);
    }

    /**
     * Сканирует несколько эндпоинтов параллельно.
     * Использует пул потоков для одновременного сканирования эндпоинтов с отслеживанием прогресса.
     *
     * @param endpoints список эндпоинтов для сканирования
     * @param context контекст сканирования
     * @return полный отчет об анализе всех эндпоинтов
     */
    public AnalysisReport scanEndpoints(List<ApiEndpoint> endpoints, ScanContext context) {
        Instant startTime = Instant.now();
        int totalEndpoints = endpoints.size();
        logger.info("Starting active analysis of " + totalEndpoints + " endpoints");

        // Calculate actual number of applicable scanners across all endpoints
        int totalApplicableScans = 0;
        for (ApiEndpoint endpoint : endpoints) {
            long applicableCount = scannerRegistry.getEnabledScanners().stream()
                .filter(scanner -> scanner.isApplicable(endpoint))
                .count();
            totalApplicableScans += applicableCount;
        }

        logger.info("Total applicable scans: " + totalApplicableScans +
                   " across " + totalEndpoints + " endpoint(s)");

        // Notify scan start with exact total count
        // Pass totalApplicableScans as first param, 1 as second to signal exact count mode
        analysisConfig.getProgressListener().onScanStart(
            "scanning", totalApplicableScans, 1);

        // Use AtomicInteger to track total vulnerabilities across all threads
        java.util.concurrent.atomic.AtomicInteger totalVulns = new java.util.concurrent.atomic.AtomicInteger(0);
        java.util.concurrent.atomic.AtomicInteger completedEndpoints = new java.util.concurrent.atomic.AtomicInteger(0);

        List<Future<EndpointAnalysisResult>> futures = new ArrayList<>();
        for (int i = 0; i < endpoints.size(); i++) {
            final int index = i;
            final ApiEndpoint endpoint = endpoints.get(i);
            futures.add(executorService.submit(() ->
                scanEndpointWithProgress(endpoint, context, index, totalEndpoints, totalVulns)
            ));
        }

        List<EndpointAnalysisResult> results = new ArrayList<>();
        for (Future<EndpointAnalysisResult> future : futures) {
            try {
                results.add(future.get());
                completedEndpoints.incrementAndGet();
            } catch (Exception e) {
                logger.warning("Endpoint scan failed: " + e.getMessage());
            }
        }

        Instant endTime = Instant.now();
        long durationSeconds = Duration.between(startTime, endTime).toSeconds();
        logger.info("Active analysis completed in " + durationSeconds + "s");

        // Notify scan complete
        analysisConfig.getProgressListener().onScanComplete(
            totalVulns.get(), durationSeconds);

        return new AnalysisReport(results, startTime, endTime);
    }

    /**
     * Возвращает реестр сканеров.
     *
     * @return реестр сканеров
     */
    public ScannerRegistry getScannerRegistry() {
        return scannerRegistry;
    }

    /**
     * Останавливает движок и освобождает ресурсы.
     * Завершает работу пула потоков и закрывает HTTP-клиент.
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
     * Конфигурация для движка активного анализа.
     * Содержит настройки криптографических протоколов, параллелизма, сканеров и отслеживания прогресса.
     */
    public static final class AnalysisConfig {
        private final HttpClient.CryptoProtocol cryptoProtocol;
        private final boolean verifySsl;
        private final int maxParallelScans;
        private final String gostPfxPath;
        private final String gostPfxPassword;
        private final boolean gostPfxResource;
        private final List<String> enabledScanners;
        private final String scanIntensity;
        private final Integer requestDelayMs;
        private final ScanProgressListener progressListener;

        private AnalysisConfig(Builder builder) {
            this.cryptoProtocol = builder.cryptoProtocol != null
                ? builder.cryptoProtocol
                : HttpClient.CryptoProtocol.STANDARD_TLS;
            this.verifySsl = builder.verifySsl;
            this.maxParallelScans = builder.maxParallelScans > 0
                ? builder.maxParallelScans
                : Runtime.getRuntime().availableProcessors();
            this.gostPfxPath = builder.gostPfxPath;
            this.gostPfxPassword = builder.gostPfxPassword;
            this.gostPfxResource = builder.gostPfxResource;
            this.enabledScanners = builder.enabledScanners;
            this.scanIntensity = builder.scanIntensity;
            this.requestDelayMs = builder.requestDelayMs;
            this.progressListener = builder.progressListener != null
                ? builder.progressListener
                : ScanProgressListener.noOp();
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

        public String getGostPfxPath() {
            return gostPfxPath;
        }

        public String getGostPfxPassword() {
            return gostPfxPassword;
        }

        public boolean isGostPfxResource() {
            return gostPfxResource;
        }

        public List<String> getEnabledScanners() {
            return enabledScanners;
        }

        public String getScanIntensity() {
            return scanIntensity;
        }

        public Integer getRequestDelayMs() {
            return requestDelayMs;
        }

        public ScanProgressListener getProgressListener() {
            return progressListener;
        }

        public static class Builder {
            private HttpClient.CryptoProtocol cryptoProtocol;
            private boolean verifySsl = true;
            private int maxParallelScans = 4;
            private String gostPfxPath;
            private String gostPfxPassword;
            private boolean gostPfxResource;
            private List<String> enabledScanners;
            private String scanIntensity;
            private Integer requestDelayMs;
            private ScanProgressListener progressListener;

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

            public Builder gostPfxPath(String gostPfxPath) {
                this.gostPfxPath = gostPfxPath;
                return this;
            }

            public Builder gostPfxPassword(String gostPfxPassword) {
                this.gostPfxPassword = gostPfxPassword;
                return this;
            }

            public Builder gostPfxResource(boolean gostPfxResource) {
                this.gostPfxResource = gostPfxResource;
                return this;
            }

            public Builder enabledScanners(List<String> enabledScanners) {
                this.enabledScanners = enabledScanners;
                return this;
            }

            public Builder scanIntensity(String scanIntensity) {
                this.scanIntensity = scanIntensity;
                return this;
            }

            public Builder requestDelayMs(Integer requestDelayMs) {
                this.requestDelayMs = requestDelayMs;
                return this;
            }

            public Builder progressListener(ScanProgressListener progressListener) {
                this.progressListener = progressListener;
                return this;
            }

            public AnalysisConfig build() {
                return new AnalysisConfig(this);
            }
        }
    }

    /**
     * Результат анализа одного эндпоинта.
     * Содержит эндпоинт, результаты сканирования и временные метки.
     *
     * @param endpoint проверенный эндпоинт
     * @param scanResults результаты всех примененных сканеров
     * @param startTime время начала анализа
     * @param endTime время окончания анализа
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
     * Полный отчет об анализе всех просканированных эндпоинтов.
     * Предоставляет агрегированную статистику, включая количество уязвимостей,
     * распределение по типам и уровням критичности.
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
