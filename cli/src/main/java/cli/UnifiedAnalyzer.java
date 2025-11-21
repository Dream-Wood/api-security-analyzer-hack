package cli;

import active.ActiveAnalysisEngine;
import active.async.AsyncAnalysisEngine;
import active.async.AsyncAnalysisReport;
import active.async.AsyncScanResult;
import active.async.AsyncVulnerabilityReport;
import active.auth.AuthCredentials;
import active.auth.AuthenticationHelper;
import active.discovery.EndpointDiscoveryEngine;
import active.discovery.model.DiscoveryConfig;
import active.discovery.model.DiscoveryResult;
import active.http.HttpClient;
import active.http.HttpClientConfig;
import active.http.HttpClientFactory;
import active.model.AnalysisProgressListener;
import active.model.ApiEndpoint;
import active.scanner.ScanContext;
import active.scanner.ScanIntensity;
import active.validator.ContractValidationEngine;
import report.AnalysisReport;
import com.fasterxml.jackson.databind.JsonNode;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.PathItem;
import model.ChannelSpec;
import model.ParameterSpec;
import model.ServerSpec;
import model.SpecificationType;
import model.ValidationFinding;
import parser.AsyncApiLoader;
import parser.AsyncSpecNormalizer;
import parser.OpenApiLoader;
import parser.SpecNormalizer;
import util.SpecTypeDetector;
import validator.AsyncContractValidator;
import validator.AsyncSecurityValidator;
import validator.StaticContractValidator;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * Унифицированный анализатор, координирующий статический и активный анализ API.
 * Основной класс для выполнения комплексного анализа безопасности OpenAPI/AsyncAPI спецификаций.
 *
 * <p>Анализатор поддерживает несколько режимов работы:
 * <ul>
 *   <li><b>STATIC_ONLY</b> - только статический анализ спецификации</li>
 *   <li><b>ACTIVE_ONLY</b> - только активное тестирование (с реальными HTTP запросами)</li>
 *   <li><b>COMBINED</b> - статический + активный анализ</li>
 *   <li><b>CONTRACT</b> - проверка соответствия реализации контракту</li>
 *   <li><b>FULL</b> - полный анализ (все типы тестов)</li>
 * </ul>
 *
 * <p>Архитектурные особенности:
 * <ul>
 *   <li>Использует {@link HttpClientHelper} для создания HTTP клиентов</li>
 *   <li>Использует {@link AuthenticationManager} для управления аутентификацией</li>
 *   <li>Поддерживает отслеживание прогресса через {@link AnalysisProgressListener}</li>
 *   <li>Работает с OpenAPI 3.x и AsyncAPI 2.x спецификациями</li>
 *   <li>Поддерживает криптографию ГОСТ (CryptoPro JCSP)</li>
 * </ul>
 *
 * <p>Пример использования:
 * <pre>{@code
 * UnifiedAnalyzer.AnalyzerConfig config = UnifiedAnalyzer.AnalyzerConfig.builder()
 *     .mode(AnalysisReport.AnalysisMode.FULL)
 *     .baseUrl("https://api.example.com")
 *     .autoAuth(true)
 *     .build();
 *
 * UnifiedAnalyzer analyzer = new UnifiedAnalyzer(config);
 * AnalysisReport report = analyzer.analyze("spec.yaml");
 * }</pre>
 *
 * @author API Security Analyzer Team
 * @since 1.0
 * @see AnalysisProgressListener
 * @see HttpClientHelper
 * @see AuthenticationManager
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
     * Выполняет анализ на основе настроенного режима работы.
     * Координирует выполнение статического анализа, активного тестирования и валидации контракта.
     *
     * <p>Процесс анализа включает следующие этапы:
     * <ol>
     *   <li>Определение типа спецификации (OpenAPI/AsyncAPI)</li>
     *   <li>Загрузка и парсинг спецификации</li>
     *   <li>Статический анализ (если включен в режиме)</li>
     *   <li>Активное тестирование безопасности (если включено в режиме)</li>
     *   <li>Валидация контракта (если включена в режиме)</li>
     *   <li>Формирование итогового отчета</li>
     * </ol>
     *
     * @param specLocation путь или URL к OpenAPI/AsyncAPI спецификации
     * @return унифицированный отчет о результатах анализа
     */
    public AnalysisReport analyze(String specLocation) {
        Instant startTime = Instant.now();

        logger.info("Starting analysis in " + config.getMode() + " mode");
        config.getProgressListener().onLog("INFO", "Starting analysis in " + config.getMode() + " mode");
        config.getProgressListener().onPhaseChange("initialization", calculateTotalSteps(config.getMode()));

        AnalysisReport.Builder reportBuilder = AnalysisReport.builder()
            .specLocation(specLocation)
            .startTime(startTime)
            .mode(config.getMode());

        // Detect specification type
        config.getProgressListener().onStepComplete(1, "Detecting specification type...");
        SpecTypeDetector.DetectionResult detection;
        try {
            detection = SpecTypeDetector.detectTypeWithVersion(specLocation);
        } catch (Exception e) {
            logger.severe("Failed to detect specification type: " + e.getMessage());
            config.getProgressListener().onLog("ERROR", "Failed to detect specification type: " + e.getMessage());
            return reportBuilder
                .endTime(Instant.now())
                .staticResult(new AnalysisReport.StaticAnalysisResult(
                    List.of(), List.of(), "Failed to detect specification type: " + e.getMessage()))
                .build();
        }

        if (!detection.isSuccess()) {
            return reportBuilder
                .endTime(Instant.now())
                .staticResult(new AnalysisReport.StaticAnalysisResult(
                    List.of(), List.of(), detection.getErrorMessage()))
                .build();
        }

        SpecificationType specType = detection.getType();
        logger.info("Detected specification type: " + specType.getDisplayName() + " " + detection.getVersion());
        config.getProgressListener().onLog("INFO", "Detected: " + specType.getDisplayName() + " " + detection.getVersion());

        // Check if AsyncAPI with non-static mode
        if (specType == SpecificationType.ASYNCAPI) {
            if (config.getMode() != AnalysisReport.AnalysisMode.STATIC_ONLY) {
                logger.warning("AsyncAPI specification detected. Only static analysis is supported for AsyncAPI.");
                logger.warning("Switching to static analysis mode...");
                config.getProgressListener().onLog("WARNING", "AsyncAPI detected - switching to static analysis");
                reportBuilder.mode(AnalysisReport.AnalysisMode.STATIC_ONLY);
            }
            return analyzeAsyncApi(specLocation, reportBuilder, startTime);
        }

        // OpenAPI analysis (existing code)
        config.getProgressListener().onStepComplete(2, "Loading OpenAPI specification...");
        OpenApiLoader.LoadResult loadResult;
        try {
            loadResult = loader.load(specLocation);
        } catch (Exception e) {
            logger.severe("Failed to load specification: " + e.getMessage());
            config.getProgressListener().onLog("ERROR", "Failed to load specification: " + e.getMessage());
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

        // Extract title from spec
        String specTitle = null;
        if (openAPI.getInfo() != null && openAPI.getInfo().getTitle() != null) {
            specTitle = openAPI.getInfo().getTitle();
        }
        reportBuilder.specTitle(specTitle);

        // Static analysis
        if (config.getMode() == AnalysisReport.AnalysisMode.STATIC_ONLY ||
            config.getMode() == AnalysisReport.AnalysisMode.COMBINED ||
            config.getMode() == AnalysisReport.AnalysisMode.FULL) {

            logger.info("Performing static analysis");
            config.getProgressListener().onLog("INFO", "Starting static analysis...");
            AnalysisReport.StaticAnalysisResult staticResult = performStaticAnalysis(
                openAPI, loadResult.getMessages());
            reportBuilder.staticResult(staticResult);
            config.getProgressListener().onLog("INFO", "Static analysis found " + staticResult.getFindings().size() + " issues");
        }

        // Active analysis
        if (config.getMode() == AnalysisReport.AnalysisMode.ACTIVE_ONLY ||
            config.getMode() == AnalysisReport.AnalysisMode.COMBINED ||
            config.getMode() == AnalysisReport.AnalysisMode.FULL) {

            // Determine base URL: use config override or extract from spec
            String baseUrl = determineBaseUrl(openAPI);

            if (baseUrl == null) {
                String error = "Active analysis requires a base URL. " +
                    "Provide --base-url parameter or define servers in OpenAPI spec";
                logger.warning(error);
                config.getProgressListener().onLog("WARNING", error);
                reportBuilder.activeResult(new AnalysisReport.ActiveAnalysisResult(null, error));
            } else {
                logger.info("Performing active analysis against: " + baseUrl);
                config.getProgressListener().onPhaseChange("active-analysis", 5);
                config.getProgressListener().onLog("INFO", "Starting active security scans against: " + baseUrl);
                AnalysisReport.ActiveAnalysisResult activeResult = performActiveAnalysis(openAPI, baseUrl, reportBuilder);
                reportBuilder.activeResult(activeResult);
                int vulnCount = (activeResult.getReport() != null ? activeResult.getReport().getTotalVulnerabilityCount() : 0);
                config.getProgressListener().onLog("INFO", "Active analysis found " + vulnCount + " vulnerabilities");
            }
        }

        // Contract validation
        if (config.getMode() == AnalysisReport.AnalysisMode.CONTRACT ||
            config.getMode() == AnalysisReport.AnalysisMode.FULL) {
            String baseUrl = determineBaseUrl(openAPI);

            if (baseUrl == null) {
                String error = "Contract validation requires a base URL. " +
                    "Provide --base-url parameter or define servers in OpenAPI spec";
                logger.warning(error);
                config.getProgressListener().onLog("WARNING", error);
                reportBuilder.contractResult(new AnalysisReport.ContractAnalysisResult(null, error));
            } else {
                logger.info("Performing contract validation against: " + baseUrl);
                config.getProgressListener().onLog("INFO", "Starting contract validation against: " + baseUrl);
                AnalysisReport.ContractAnalysisResult contractResult =
                    performContractValidation(openAPI, baseUrl);
                reportBuilder.contractResult(contractResult);
                config.getProgressListener().onLog("INFO", "Contract validation completed");
            }
        }

        reportBuilder.endTime(Instant.now());
        return reportBuilder.build();
    }

    private AnalysisReport.StaticAnalysisResult performStaticAnalysis(
            OpenAPI openAPI, List<String> parsingMessages) {
        try {
            // Count total operations for progress tracking
            int totalOperations = 0;
            if (openAPI.getPaths() != null) {
                for (var path : openAPI.getPaths().values()) {
                    if (path.getGet() != null) totalOperations++;
                    if (path.getPost() != null) totalOperations++;
                    if (path.getPut() != null) totalOperations++;
                    if (path.getPatch() != null) totalOperations++;
                    if (path.getDelete() != null) totalOperations++;
                    if (path.getHead() != null) totalOperations++;
                    if (path.getOptions() != null) totalOperations++;
                }
            }

            config.getProgressListener().onLog("INFO", "Found " + totalOperations + " operations to analyze");
            config.getProgressListener().onPhaseChange("static-analysis", totalOperations > 0 ? totalOperations : 1);

            config.getProgressListener().onStepComplete(1, "Analyzing OpenAPI specification structure...");

            StaticContractValidator validator = new StaticContractValidator(openAPI);
            List<ValidationFinding> findings = validator.validate();

            // Mark all operations as analyzed
            if (totalOperations > 0) {
                config.getProgressListener().onStepComplete(totalOperations,
                    "Static analysis completed: " + findings.size() + " findings");
            }

            logger.info("Static analysis completed: " + findings.size() + " findings");
            return new AnalysisReport.StaticAnalysisResult(parsingMessages, findings, null);

        } catch (Exception e) {
            logger.severe("Static analysis failed: " + e.getMessage());
            config.getProgressListener().onLog("ERROR", "Static analysis failed: " + e.getMessage());
            return new AnalysisReport.StaticAnalysisResult(
                parsingMessages, List.of(), "Static analysis failed: " + e.getMessage());
        }
    }

    /**
     * Определяет базовый URL для активного анализа.
     * Приоритет: параметр конфигурации > первый сервер в спецификации > null
     *
     * @param openAPI объект OpenAPI спецификации
     * @return базовый URL для тестирования или null если URL не найден
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

    private AnalysisReport.ActiveAnalysisResult performActiveAnalysis(OpenAPI openAPI, String baseUrl,
                                                                      AnalysisReport.Builder reportBuilder) {
        ActiveAnalysisEngine engine = null;
        EndpointDiscoveryEngine discoveryEngine = null;
        try {
            // Create and configure analysis engine
            ActiveAnalysisEngine.AnalysisConfig.Builder analysisConfigBuilder =
                ActiveAnalysisEngine.AnalysisConfig.builder()
                    .cryptoProtocol(config.getCryptoProtocol())
                    .verifySsl(config.isVerifySsl())
                    .maxParallelScans(config.getMaxParallelScans());

            // Add GOST configuration if provided
            if (config.getGostPfxPath() != null) {
                analysisConfigBuilder.gostPfxPath(config.getGostPfxPath());
            }
            if (config.getGostPfxPassword() != null) {
                analysisConfigBuilder.gostPfxPassword(config.getGostPfxPassword());
            }
            analysisConfigBuilder.gostPfxResource(config.isGostPfxResource());

            // Add enabled scanners if provided
            if (config.getEnabledScanners() != null) {
                analysisConfigBuilder.enabledScanners(config.getEnabledScanners());
            }

            // Add scan intensity configuration
            if (config.getScanIntensity() != null) {
                analysisConfigBuilder.scanIntensity(config.getScanIntensity());
            }

            // Add custom request delay
            if (config.getRequestDelayMs() != null) {
                analysisConfigBuilder.requestDelayMs(config.getRequestDelayMs());
            }

            // Bridge AnalysisProgressListener to ScanProgressListener
            analysisConfigBuilder.progressListener(new active.ScanProgressListener() {
                private final java.util.concurrent.atomic.AtomicInteger completedScans =
                    new java.util.concurrent.atomic.AtomicInteger(0);

                @Override
                public void onScanStart(String phase, int totalEndpoints, int totalScanners) {
                    // If totalScanners == 1, totalEndpoints contains the exact total scan count
                    int totalScans = (totalScanners == 1) ? totalEndpoints : (totalEndpoints * totalScanners);

                    // Reset counter and set total steps based on actual scan operations
                    completedScans.set(0);
                    config.getProgressListener().onPhaseChange("active-scanning", totalScans);

                    if (totalScanners == 1) {
                        config.getProgressListener().onLog("INFO", String.format(
                            "Starting scan: %d total scanner operations", totalScans));
                    } else {
                        config.getProgressListener().onLog("INFO", String.format(
                            "Starting scan: %d endpoints × %d scanners = %d total scans",
                            totalEndpoints, totalScanners, totalScans));
                    }
                }

                @Override
                public void onEndpointStart(int endpointIndex, int totalEndpoints, String endpoint) {
                    config.getProgressListener().onLog("INFO",
                        String.format("Scanning endpoint %d/%d: %s", endpointIndex + 1, totalEndpoints, endpoint));
                }

                @Override
                public void onScannerStart(String scannerName, int scannerIndex, int totalScanners) {
                    config.getProgressListener().onLog("DEBUG",
                        String.format("  Running scanner %d/%d: %s", scannerIndex + 1, totalScanners, scannerName));
                }

                @Override
                public void onScannerComplete(String scannerName, int vulnerabilityCount) {
                    // Each scanner completion is one step
                    int currentStep = completedScans.incrementAndGet();
                    config.getProgressListener().onStepComplete(currentStep, null);

                    if (vulnerabilityCount > 0) {
                        config.getProgressListener().onLog("WARNING",
                            String.format("  ⚠ %s found %d vulnerability(ies)", scannerName, vulnerabilityCount));
                    }
                }

                @Override
                public void onEndpointComplete(int endpointIndex, int totalEndpoints, int totalVulnerabilities) {
                    config.getProgressListener().onLog("INFO",
                        String.format("✓ Completed %d/%d endpoints (%d vulnerabilities so far)",
                            endpointIndex + 1, totalEndpoints, totalVulnerabilities));
                }

                @Override
                public void onScanComplete(int totalVulnerabilities, long durationSeconds) {
                    config.getProgressListener().onLog("INFO",
                        String.format("✓ Scan complete: found %d vulnerabilities in %ds",
                            totalVulnerabilities, durationSeconds));
                }
            });

            ActiveAnalysisEngine.AnalysisConfig analysisConfig = analysisConfigBuilder.build();

            engine = new ActiveAnalysisEngine(analysisConfig);
            // Scanners are auto-registered via ServiceLoader (see META-INF/services)

            // Extract endpoints from OpenAPI spec
            config.getProgressListener().onStepComplete(1, "Parsing API endpoints from specification...");
            List<ApiEndpoint> endpoints = extractEndpoints(openAPI);
            logger.info("Extracted " + endpoints.size() + " documented endpoints for active scanning");
            config.getProgressListener().onLog("INFO", "Found " + endpoints.size() + " documented endpoints");

            // Run Endpoint Discovery if enabled
            if (config.isEnableDiscovery()) {
                try {
                    logger.info("Endpoint Discovery is enabled, starting discovery phase...");
                    config.getProgressListener().onLog("INFO", "Starting Endpoint Discovery to find undocumented endpoints...");
                    // DO NOT call onPhaseChange here - EndpointDiscoveryEngine will set it with accurate step count

                    // Create HTTP client for discovery
                    HttpClientConfig.Builder httpConfigBuilder = HttpClientConfig.builder()
                        .cryptoProtocol(config.getCryptoProtocol())
                        .connectTimeout(java.time.Duration.ofSeconds(30))
                        .readTimeout(java.time.Duration.ofSeconds(30))
                        .followRedirects(true)
                        .verifySsl(config.isVerifySsl());

                    // Add GOST configuration if provided
                    if (config.getGostPfxPath() != null) {
                        httpConfigBuilder.addCustomSetting("pfxPath", config.getGostPfxPath());
                    }
                    if (config.getGostPfxPassword() != null) {
                        httpConfigBuilder.addCustomSetting("pfxPassword", config.getGostPfxPassword());
                    }
                    if (config.isGostPfxResource()) {
                        httpConfigBuilder.addCustomSetting("pfxResource", "true");
                    }

                    HttpClient discoveryHttpClient = HttpClientFactory.createClient(httpConfigBuilder.build());

                    // Create Discovery configuration
                    DiscoveryConfig.Builder discoveryConfigBuilder = DiscoveryConfig.builder();

                    // Set strategy
                    if (config.getDiscoveryStrategy() != null) {
                        // Convert "top-down" to "TOP_DOWN" for enum parsing
                        String strategyName = config.getDiscoveryStrategy().toUpperCase().replace("-", "_");
                        discoveryConfigBuilder.strategy(
                            DiscoveryConfig.DiscoveryStrategy.valueOf(strategyName)
                        );
                    } else {
                        discoveryConfigBuilder.strategy(DiscoveryConfig.DiscoveryStrategy.HYBRID);
                    }

                    // Set max depth
                    if (config.getDiscoveryMaxDepth() != null) {
                        discoveryConfigBuilder.maxDepth(config.getDiscoveryMaxDepth());
                    }

                    // Set max requests
                    if (config.getDiscoveryMaxRequests() != null) {
                        discoveryConfigBuilder.maxTotalRequests(config.getDiscoveryMaxRequests());
                    }

                    // Set request delay (use scanIntensity or custom requestDelayMs)
                    int discoveryDelayMs = 100; // Default
                    if (config.getRequestDelayMs() != null) {
                        discoveryDelayMs = config.getRequestDelayMs();
                    } else if (config.getScanIntensity() != null) {
                        // Map scan intensity to delay
                        discoveryDelayMs = switch (config.getScanIntensity().toLowerCase()) {
                            case "low" -> 500;
                            case "medium" -> 200;
                            case "high" -> 100;
                            case "aggressive" -> 50;
                            default -> 100;
                        };
                    }
                    discoveryConfigBuilder.requestDelayMs(discoveryDelayMs);

                    // Set fast cancel
                    discoveryConfigBuilder.fastCancel(config.isDiscoveryFastCancel());

                    // Set wordlist directory
                    if (config.getWordlistDir() != null) {
                        discoveryConfigBuilder.wordlistDirectory(config.getWordlistDir());
                    }

                    // Set verbose mode
                    discoveryConfigBuilder.verbose(config.isVerbose());

                    DiscoveryConfig discoveryConfig = discoveryConfigBuilder.build();

                    // Create Discovery engine with progress listener
                    discoveryEngine = new EndpointDiscoveryEngine(
                        discoveryHttpClient,
                        discoveryConfig,
                        config.getProgressListener()
                    );

                    // Get operations from spec for Discovery
                    SpecNormalizer normalizer = new SpecNormalizer();
                    var operations = normalizer.normalize(openAPI);

                    // Run discovery - progress will be reported by EndpointDiscoveryEngine
                    EndpointDiscoveryEngine.DiscoveryReport discoveryReport =
                        discoveryEngine.discover(operations, baseUrl);

                    logger.info("Endpoint Discovery completed: found " + discoveryReport.getTotalCount() +
                        " undocumented endpoint(s) in " + discoveryReport.getDuration().toSeconds() + "s");

                    // Add discovery results to report
                    reportBuilder.discoveryResult(
                        new AnalysisReport.DiscoveryAnalysisResult(discoveryReport, null)
                    );

                    // Convert discovered endpoints to ApiEndpoint and add to scan list
                    if (discoveryReport.hasFindings()) {
                        List<ApiEndpoint> discoveredEndpoints = new ArrayList<>();
                        for (DiscoveryResult result : discoveryReport.getResults()) {
                            ApiEndpoint discoveredEndpoint = ApiEndpoint.builder()
                                .path(result.getEndpoint().getPath())
                                .method(result.getEndpoint().getMethod())
                                .addMetadata("discovered", true)
                                .addMetadata("discoveryMethod", result.getDiscoveryMethod().name())
                                .addMetadata("confidence", result.getMetadata().get("confidence"))
                                .addMetadata("severity", result.getSeverity().name())
                                .build();
                            discoveredEndpoints.add(discoveredEndpoint);
                        }

                        endpoints.addAll(discoveredEndpoints);
                        logger.info("Added " + discoveredEndpoints.size() +
                            " discovered endpoints to scan queue. Total endpoints to scan: " + endpoints.size());
                        config.getProgressListener().onLog("INFO",
                            "Total endpoints to scan: " + endpoints.size() +
                            " (" + discoveredEndpoints.size() + " discovered)");
                    }

                    // Close discovery HTTP client
                    discoveryHttpClient.close();

                } catch (Exception e) {
                    logger.warning("Endpoint Discovery failed: " + e.getMessage());
                    config.getProgressListener().onLog("WARNING", "Endpoint Discovery failed: " + e.getMessage());
                    reportBuilder.discoveryResult(
                        new AnalysisReport.DiscoveryAnalysisResult(null,
                            "Discovery failed: " + e.getMessage())
                    );
                    // Continue with documented endpoints only
                }
            }

            if (endpoints.isEmpty()) {
                logger.warning("No endpoints found in specification");
                config.getProgressListener().onLog("WARNING", "No endpoints found in specification");
                return new AnalysisReport.ActiveAnalysisResult(
                    null, "No endpoints found in specification");
            }

            // Check if scanners are disabled (Discovery-only mode)
            boolean scannersDisabled = config.getEnabledScanners() != null && config.getEnabledScanners().isEmpty();

            if (scannersDisabled) {
                logger.info("All vulnerability scanners disabled - Discovery-only mode");
                config.getProgressListener().onLog("INFO", "✓ Discovery-only mode - vulnerability scanning skipped");
                config.getProgressListener().onPhaseChange("active-analysis", 1);
                config.getProgressListener().onStepComplete(1, "Skipping vulnerability scans (Discovery-only mode)");
                // Return empty report (no vulnerabilities scanned)
                java.time.Instant now = java.time.Instant.now();
                return new AnalysisReport.ActiveAnalysisResult(
                    new ActiveAnalysisEngine.AnalysisReport(List.of(), now, now),
                    null
                );
            }

            // Create scan context
            ScanContext.Builder contextBuilder = ScanContext.builder()
                .baseUrl(baseUrl)
                .verbose(config.isVerbose());

            // Setup authentication using AuthenticationManager
            AuthenticationManager authManager = new AuthenticationManager(config);
            authManager.setupAuthentication(contextBuilder, baseUrl, endpoints);

            ScanContext context = contextBuilder.build();

            // Execute scan
            config.getProgressListener().onStepComplete(4, "Starting security vulnerability scans...");
            config.getProgressListener().onLog("INFO", "Scanning " + endpoints.size() + " endpoint(s) for vulnerabilities...");
            ActiveAnalysisEngine.AnalysisReport activeReport = engine.scanEndpoints(endpoints, context);

            logger.info("Active analysis completed: " +
                activeReport.getTotalVulnerabilityCount() + " vulnerabilities found");
            config.getProgressListener().onStepComplete(5, "Security scans completed");
            config.getProgressListener().onLog("INFO", "✓ Scanning complete - found " +
                activeReport.getTotalVulnerabilityCount() + " vulnerabilities");

            return new AnalysisReport.ActiveAnalysisResult(activeReport, null);

        } catch (Exception e) {
            logger.severe("Active analysis failed: " + e.getMessage());
            config.getProgressListener().onLog("ERROR", "Active analysis failed: " + e.getMessage());
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
            // Extract endpoints from OpenAPI spec
            List<ApiEndpoint> endpoints = extractEndpoints(openAPI);
            logger.info("Extracted " + endpoints.size() + " endpoints for contract validation");
            config.getProgressListener().onLog("INFO", "Found " + endpoints.size() + " endpoints to validate");

            if (endpoints.isEmpty()) {
                logger.warning("No endpoints found in specification");
                config.getProgressListener().onLog("WARNING", "No endpoints found in specification");
                return new AnalysisReport.ContractAnalysisResult(
                    null, "No endpoints found in specification");
            }

            // Set up progress tracking for contract validation
            config.getProgressListener().onPhaseChange("contract-validation", endpoints.size());
            config.getProgressListener().onStepComplete(1, "Preparing contract validation...");

            // Create contract validation engine
            boolean fuzzingEnabled = !config.isNoFuzzing();
            ContractValidationEngine engine = new ContractValidationEngine(openAPI, baseUrl, fuzzingEnabled);

            // Create HTTP client
            HttpClient httpClient = HttpClientHelper.createClient(config);

            // Validate endpoints with progress tracking
            config.getProgressListener().onLog("INFO", "Validating " + endpoints.size() + " endpoint(s) against contract...");

            // Manually track progress during validation
            ContractValidationEngine.ContractValidationReport report = validateEndpointsWithProgress(
                engine, endpoints, httpClient);

            config.getProgressListener().onStepComplete(endpoints.size(),
                "Contract validation completed: " + report.getTotalDivergences() + " divergences");

            logger.info("Contract validation completed: " +
                report.getTotalDivergences() + " divergences found");

            return new AnalysisReport.ContractAnalysisResult(report, null);

        } catch (Exception e) {
            logger.severe("Contract validation failed: " + e.getMessage());
            config.getProgressListener().onLog("ERROR", "Contract validation failed: " + e.getMessage());
            return new AnalysisReport.ContractAnalysisResult(
                null, "Contract validation failed: " + e.getMessage());
        }
    }

    /**
     * Validates endpoints with progress tracking.
     */
    private ContractValidationEngine.ContractValidationReport validateEndpointsWithProgress(
            ContractValidationEngine engine,
            List<ApiEndpoint> endpoints,
            HttpClient httpClient) {

        Instant startTime = Instant.now();
        List<active.validator.model.ValidationResult> results = new ArrayList<>();

        for (int i = 0; i < endpoints.size(); i++) {
            ApiEndpoint endpoint = endpoints.get(i);
            String endpointStr = endpoint.getMethod() + " " + endpoint.getPath();

            config.getProgressListener().onStepComplete(i + 1,
                "Validating " + (i + 1) + "/" + endpoints.size() + ": " + endpointStr);

            try {
                active.validator.model.ValidationResult result = engine.validateEndpoint(endpoint, httpClient);
                results.add(result);

                if (result.hasDivergences()) {
                    config.getProgressListener().onLog("WARNING",
                        "  ⚠ Found " + result.getDivergences().size() + " divergence(s) in " + endpointStr);
                } else {
                    config.getProgressListener().onLog("DEBUG",
                        "  ✓ " + endpointStr + " matches contract");
                }
            } catch (Exception e) {
                logger.warning("Failed to validate " + endpointStr + ": " + e.getMessage());
                config.getProgressListener().onLog("WARNING",
                    "  ✗ Failed to validate " + endpointStr + ": " + e.getMessage());
            }
        }

        Instant endTime = Instant.now();
        boolean fuzzingEnabled = !config.isNoFuzzing();

        return new ContractValidationEngine.ContractValidationReport(
            results, startTime, endTime, fuzzingEnabled);
    }

    /**
     * Извлекает конечные точки API из OpenAPI спецификации.
     * Преобразует пути и операции спецификации в объекты {@link ApiEndpoint}.
     *
     * @param openAPI объект OpenAPI спецификации
     * @return список конечных точек API
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
     * Анализирует AsyncAPI спецификацию (только статический анализ).
     * AsyncAPI не поддерживает активное тестирование, поэтому выполняется только статическая валидация.
     *
     * @param specLocation путь или URL к AsyncAPI спецификации
     * @param reportBuilder билдер отчета для формирования результата
     * @param startTime время начала анализа
     * @return отчет с результатами статического анализа AsyncAPI
     */
    private AnalysisReport analyzeAsyncApi(String specLocation,
                                           AnalysisReport.Builder reportBuilder,
                                           Instant startTime) {
        logger.info("Analyzing AsyncAPI specification");

        // Load AsyncAPI specification
        AsyncApiLoader asyncLoader = new AsyncApiLoader();
        AsyncApiLoader.LoadResult loadResult;

        try {
            loadResult = asyncLoader.load(specLocation);
        } catch (Exception e) {
            logger.severe("Failed to load AsyncAPI specification: " + e.getMessage());
            return reportBuilder
                .endTime(Instant.now())
                .staticResult(new AnalysisReport.StaticAnalysisResult(
                    List.of(), List.of(), "Failed to load AsyncAPI specification: " + e.getMessage()))
                .build();
        }

        if (!loadResult.isSuccessful()) {
            String error = "Failed to parse AsyncAPI specification";
            if (!loadResult.getMessages().isEmpty()) {
                error += ": " + String.join(", ", loadResult.getMessages());
            }
            return reportBuilder
                .endTime(Instant.now())
                .staticResult(new AnalysisReport.StaticAnalysisResult(
                    loadResult.getMessages(), List.of(), error))
                .build();
        }

        JsonNode asyncApiNode = loadResult.getAsyncApiNode();

        // Extract title from spec
        String specTitle = null;
        if (asyncApiNode.has("info") && asyncApiNode.get("info").has("title")) {
            specTitle = asyncApiNode.get("info").get("title").asText();
        }
        reportBuilder.specTitle(specTitle);

        // Perform static analysis if needed
        if (config.mode != AnalysisReport.AnalysisMode.ACTIVE_ONLY) {
            logger.info("Performing static analysis on AsyncAPI specification");
            AnalysisReport.StaticAnalysisResult staticResult =
                performAsyncStaticAnalysis(asyncApiNode, loadResult.getMessages());
            reportBuilder.staticResult(staticResult);
        }

        // Perform active analysis if needed
        if (config.mode != AnalysisReport.AnalysisMode.STATIC_ONLY) {
            logger.info("Performing active analysis on AsyncAPI specification");
            try {
                AsyncAnalysisReport activeResult = performAsyncActiveAnalysis(asyncApiNode);
                // TODO: Convert AsyncAnalysisReport to format compatible with AnalysisReport
                // For now, just log the results
                logger.info(String.format("AsyncAPI active analysis completed: %d vulnerabilities found",
                        activeResult.getTotalVulnerabilities()));
                logger.info(activeResult.getSummary());
            } catch (Exception e) {
                logger.severe("AsyncAPI active analysis failed: " + e.getMessage());
            }
        }

        reportBuilder.endTime(Instant.now());
        return reportBuilder.build();
    }

    /**
     * Performs static analysis on AsyncAPI specification.
     */
    private AnalysisReport.StaticAnalysisResult performAsyncStaticAnalysis(
            JsonNode asyncApiNode, List<String> parsingMessages) {
        try {
            List<ValidationFinding> allFindings = new ArrayList<>();

            // Contract validation
            AsyncContractValidator contractValidator = new AsyncContractValidator(asyncApiNode);
            List<ValidationFinding> contractFindings = contractValidator.validate();
            allFindings.addAll(contractFindings);
            logger.info("Contract validation completed: " + contractFindings.size() + " findings");

            // Security validation
            AsyncSecurityValidator securityValidator = new AsyncSecurityValidator(asyncApiNode);
            List<ValidationFinding> securityFindings = securityValidator.validate();
            allFindings.addAll(securityFindings);
            logger.info("Security validation completed: " + securityFindings.size() + " findings");

            logger.info("AsyncAPI static analysis completed: " + allFindings.size() + " total findings");
            return new AnalysisReport.StaticAnalysisResult(parsingMessages, allFindings, null);

        } catch (Exception e) {
            logger.severe("Static analysis failed: " + e.getMessage());
            return new AnalysisReport.StaticAnalysisResult(
                parsingMessages, List.of(), "Static analysis failed: " + e.getMessage());
        }
    }

    /**
     * Performs active analysis on AsyncAPI specification.
     * Uses AsyncAnalysisEngine to test async operations with protocol clients and scanners.
     *
     * @param asyncApiNode the AsyncAPI specification node
     * @return AsyncAnalysisReport with vulnerability findings
     */
    private AsyncAnalysisReport performAsyncActiveAnalysis(JsonNode asyncApiNode) {
        logger.info("Starting AsyncAPI active analysis");

        try {
            // Parse AsyncAPI specification to extract channels and servers
            AsyncSpecNormalizer normalizer = new AsyncSpecNormalizer();
            List<ChannelSpec> channels = normalizer.normalize(asyncApiNode);
            Map<String, ServerSpec> servers = normalizer.extractServers(asyncApiNode);

            logger.info(String.format("Parsed AsyncAPI: %d channel(s), %d server(s)",
                    channels.size(), servers.size()));

            // Determine scan intensity
            ScanIntensity intensity = ScanIntensity.MEDIUM; // default
            if (config.scanIntensity != null) {
                try {
                    intensity = ScanIntensity.valueOf(config.scanIntensity.toUpperCase());
                } catch (IllegalArgumentException e) {
                    logger.warning("Invalid scan intensity: " + config.scanIntensity + ", using MEDIUM");
                }
            }

            // Build scan context
            ScanContext scanContext = ScanContext.builder()
                    .scanIntensity(intensity)
                    .maxRequestsPerEndpoint(100) // reasonable limit
                    .build();

            // Create AsyncAnalysisEngine
            AsyncAnalysisEngine engine = new AsyncAnalysisEngine.Builder()
                    .withThreadPoolSize(config.maxParallelScans)
                    .withScanContext(scanContext)
                    .withPluginsDirectory("plugins")
                    .withAutoDiscoverPlugins(true)
                    .build();

            // Execute analysis
            AsyncAnalysisReport report = engine.analyze(channels, servers);

            // Cleanup
            engine.shutdown();

            logger.info(String.format("AsyncAPI active analysis completed: %d vulnerabilities found in %dms",
                    report.getTotalVulnerabilities(), report.getDurationMs()));

            return report;

        } catch (Exception e) {
            logger.severe("AsyncAPI active analysis failed: " + e.getMessage());
            e.printStackTrace();
            // Return empty report on failure
            return new AsyncAnalysisReport(List.of(), 0);
        }
    }

    /**
     * Calculate total steps for progress tracking based on analysis mode.
     */
    private static int calculateTotalSteps(AnalysisReport.AnalysisMode mode) {
        return switch (mode) {
            case STATIC_ONLY -> 3;  // detect, load, analyze
            case ACTIVE_ONLY -> 7;  // detect, load, parse, auth, scan (3 scanners avg)
            case COMBINED, CONTRACT, FULL -> 10; // detect, load, static, active, report
        };
    }


    /**
     * Конфигурация унифицированного анализатора.
     * Содержит все параметры, необходимые для выполнения различных типов анализа.
     *
     * <p>Используйте {@link Builder} для создания экземпляров конфигурации:
     * <pre>{@code
     * AnalyzerConfig config = AnalyzerConfig.builder()
     *     .mode(AnalysisMode.FULL)
     *     .baseUrl("https://api.example.com")
     *     .cryptoProtocol(HttpClient.CryptoProtocol.CRYPTOPRO_JCSP)
     *     .gostPfxPath("cert.pfx")
     *     .autoAuth(true)
     *     .build();
     * }</pre>
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
        private final String gostPfxPath;
        private final String gostPfxPassword;
        private final boolean gostPfxResource;
        private final boolean useLowLevelSocket;
        private final String targetIP;
        private final String sniHostname;
        private final List<String> enabledScanners;
        private final String scanIntensity;
        private final Integer requestDelayMs;
        private final List<AuthCredentials> testUsers;
        private final AnalysisProgressListener progressListener;

        // Discovery options
        private final boolean enableDiscovery;
        private final String discoveryStrategy;
        private final Integer discoveryMaxDepth;
        private final Integer discoveryMaxRequests;
        private final boolean discoveryFastCancel;
        private final String wordlistDir;

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
            this.gostPfxPath = builder.gostPfxPath;
            this.gostPfxPassword = builder.gostPfxPassword;
            this.gostPfxResource = builder.gostPfxResource;
            this.useLowLevelSocket = builder.useLowLevelSocket;
            this.targetIP = builder.targetIP;
            this.sniHostname = builder.sniHostname;
            this.enabledScanners = builder.enabledScanners;
            this.scanIntensity = builder.scanIntensity;
            this.requestDelayMs = builder.requestDelayMs;
            this.testUsers = builder.testUsers;
            this.progressListener = builder.progressListener != null ? builder.progressListener : AnalysisProgressListener.noOp();

            // Discovery
            this.enableDiscovery = builder.enableDiscovery;
            this.discoveryStrategy = builder.discoveryStrategy;
            this.discoveryMaxDepth = builder.discoveryMaxDepth;
            this.discoveryMaxRequests = builder.discoveryMaxRequests;
            this.discoveryFastCancel = builder.discoveryFastCancel;
            this.wordlistDir = builder.wordlistDir;
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

        public String getGostPfxPath() {
            return gostPfxPath;
        }

        public String getGostPfxPassword() {
            return gostPfxPassword;
        }

        public boolean isGostPfxResource() {
            return gostPfxResource;
        }

        public boolean isUseLowLevelSocket() {
            return useLowLevelSocket;
        }

        public String getTargetIP() {
            return targetIP;
        }

        public String getSniHostname() {
            return sniHostname;
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

        public List<AuthCredentials> getTestUsers() {
            return testUsers;
        }

        public AnalysisProgressListener getProgressListener() {
            return progressListener;
        }

        public boolean isEnableDiscovery() {
            return enableDiscovery;
        }

        public String getDiscoveryStrategy() {
            return discoveryStrategy;
        }

        public Integer getDiscoveryMaxDepth() {
            return discoveryMaxDepth;
        }

        public Integer getDiscoveryMaxRequests() {
            return discoveryMaxRequests;
        }

        public boolean isDiscoveryFastCancel() {
            return discoveryFastCancel;
        }

        public String getWordlistDir() {
            return wordlistDir;
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
            private String gostPfxPath;
            private String gostPfxPassword;
            private boolean gostPfxResource;
            private boolean useLowLevelSocket;
            private String targetIP;
            private String sniHostname;
            private List<String> enabledScanners;
            private String scanIntensity;
            private Integer requestDelayMs;
            private List<AuthCredentials> testUsers;
            private AnalysisProgressListener progressListener;

            // Discovery options
            private boolean enableDiscovery;
            private String discoveryStrategy;
            private Integer discoveryMaxDepth;
            private Integer discoveryMaxRequests;
            private boolean discoveryFastCancel;
            private String wordlistDir;

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

            public Builder useLowLevelSocket(boolean useLowLevelSocket) {
                this.useLowLevelSocket = useLowLevelSocket;
                return this;
            }

            public Builder targetIP(String targetIP) {
                this.targetIP = targetIP;
                return this;
            }

            public Builder sniHostname(String sniHostname) {
                this.sniHostname = sniHostname;
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

            public Builder testUsers(List<AuthCredentials> testUsers) {
                this.testUsers = testUsers;
                return this;
            }

            public Builder progressListener(AnalysisProgressListener progressListener) {
                this.progressListener = progressListener;
                return this;
            }

            public Builder enableDiscovery(boolean enableDiscovery) {
                this.enableDiscovery = enableDiscovery;
                return this;
            }

            public Builder discoveryStrategy(String discoveryStrategy) {
                this.discoveryStrategy = discoveryStrategy;
                return this;
            }

            public Builder discoveryMaxDepth(Integer discoveryMaxDepth) {
                this.discoveryMaxDepth = discoveryMaxDepth;
                return this;
            }

            public Builder discoveryMaxRequests(Integer discoveryMaxRequests) {
                this.discoveryMaxRequests = discoveryMaxRequests;
                return this;
            }

            public Builder discoveryFastCancel(boolean discoveryFastCancel) {
                this.discoveryFastCancel = discoveryFastCancel;
                return this;
            }

            public Builder wordlistDir(String wordlistDir) {
                this.wordlistDir = wordlistDir;
                return this;
            }

            public AnalyzerConfig build() {
                return new AnalyzerConfig(this);
            }
        }
    }
}
