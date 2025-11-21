package webui.service;

import active.ActiveAnalysisEngine;
import active.async.AsyncAnalysisEngine;
import active.async.AsyncAnalysisReport;
import active.async.AsyncScannerAutoDiscovery;
import active.async.AsyncScannerRegistry;
import active.async.AsyncVulnerabilityScanner;
import active.http.HttpClient;
import active.model.AnalysisProgressListener;
import active.protocol.ProtocolClient;
import active.protocol.ProtocolConfig;
import active.protocol.ProtocolPluginLoader;
import active.protocol.ProtocolRegistry;
import active.scanner.ScanContext;
import active.scanner.ScanIntensity;
import active.scanner.ScannerAutoDiscovery;
import active.scanner.ScannerRegistry;
import active.scanner.VulnerabilityScanner;
import cli.UnifiedAnalyzer;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.annotation.PreDestroy;
import model.ChannelSpec;
import model.ServerSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import parser.AsyncApiLoader;
import parser.AsyncSpecNormalizer;
import report.AnalysisReport;
import util.CryptoProtocolParser;
import util.ModeParser;
import util.StringUtils;
import validator.AsyncContractValidator;
import validator.AsyncSecurityValidator;
import webui.model.*;
import webui.websocket.AnalysisWebSocketHandler;

import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Сервис управления операциями анализа безопасности API.
 */
@Service
public class AnalysisService {
    private static final Logger logger = LoggerFactory.getLogger(AnalysisService.class);

    private final ScannerRegistry scannerRegistry;
    private final Map<String, AnalysisSession> activeSessions = new ConcurrentHashMap<>();
    private final ExecutorService executorService = Executors.newCachedThreadPool();
    private final AnalysisWebSocketHandler webSocketHandler;

    // Маппинг scanner ID на имя bundle для .properties файлов
    private static final Map<String, String> SCANNER_ID_TO_BUNDLE = Map.ofEntries(
        Map.entry("bola-scanner", "bola"),
        Map.entry("broken-authentication-scanner", "brokenauth"),
        Map.entry("broken-function-level-auth-scanner", "bfla"),
        Map.entry("broken-object-property-auth-scanner", "bopla"),
        Map.entry("command-injection-scanner", "injection"),
        Map.entry("improper-inventory-scanner", "inventory"),
        Map.entry("information-disclosure-scanner", "infodisclosure"),
        Map.entry("path-traversal-scanner", "traversal"),
        Map.entry("security-misconfiguration-scanner", "misconfiguration"),
        Map.entry("sql-injection-scanner", "sqlinjection"),
        Map.entry("ssrf-scanner", "ssrf"),
        Map.entry("unrestricted-business-flow-scanner", "businessflow"),
        Map.entry("unrestricted-resource-scanner", "resource"),
        Map.entry("unsafe-api-consumption-scanner", "unsafeapi"),
        Map.entry("weak-cryptography-scanner", "crypto"),
        Map.entry("xxe-scanner", "xxe"),
        Map.entry("unauthorized-subscription-scanner", "asyncauth")
    );

    public AnalysisService(AnalysisWebSocketHandler webSocketHandler) {
        this.webSocketHandler = webSocketHandler;
        this.scannerRegistry = new ScannerRegistry();

        // Auto-discover and register OpenAPI scanners
        int registered = ScannerAutoDiscovery.discoverAndRegister(scannerRegistry);
        logger.info("Registered {} OpenAPI scanners", registered);

        // Auto-discover and register AsyncAPI scanners (deferred initialization)
        // Using CompletableFuture to avoid blocking Spring context initialization
        CompletableFuture.runAsync(this::initializeAsyncApiPlugins);
    }

    /**
     * Initialize AsyncAPI scanners and protocol clients.
     * Runs asynchronously to avoid blocking Spring context initialization.
     */
    private void initializeAsyncApiPlugins() {
        logger.info("Starting AsyncAPI plugins initialization...");

        try {
            AsyncScannerAutoDiscovery asyncScannerDiscovery = new AsyncScannerAutoDiscovery("plugins");
            List<AsyncVulnerabilityScanner> asyncScanners = asyncScannerDiscovery.discoverAndRegister();
            logger.info("Registered {} AsyncAPI scanners", asyncScanners.size());
        } catch (Throwable t) {
            logger.warn("Failed to load AsyncAPI scanners: {}", t.getMessage(), t);
        }

        try {
            ProtocolPluginLoader protocolLoader = new ProtocolPluginLoader("plugins");
            List<ProtocolClient> protocolClients = protocolLoader.discoverProtocolClients();
            logger.info("Registered {} Protocol clients", protocolClients.size());
        } catch (Throwable t) {
            logger.warn("Failed to load Protocol clients: {}", t.getMessage(), t);
        }

        logger.info("AsyncAPI plugins initialization completed");
    }

    /**
     * Корректное завершение работы executor service при остановке приложения.
     */
    @PreDestroy
    public void cleanup() {
        logger.info("Shutting down analysis executor service...");
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(60, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
                if (!executorService.awaitTermination(60, TimeUnit.SECONDS)) {
                    logger.error("Executor service did not terminate");
                }
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
        logger.info("Analysis executor service shutdown complete");
    }

    /**
     * Получение информации обо всех доступных сканерах.
     */
    public List<ScannerInfo> getAvailableScanners() {
        return scannerRegistry.getAllScanners().stream()
            .map(this::toScannerInfo)
            .sorted(Comparator.comparing(ScannerInfo::category).thenComparing(ScannerInfo::name))
            .collect(Collectors.toList());
    }

    /**
     * Запуск новой сессии анализа.
     */
    public String startAnalysis(AnalysisRequest request) {
        String sessionId = UUID.randomUUID().toString();

        AnalysisSession session = new AnalysisSession(sessionId);
        session.setWebSocketHandler(webSocketHandler);
        activeSessions.put(sessionId, session);

        // Run analysis in background
        CompletableFuture<Void> analysisTask = CompletableFuture.runAsync(() -> {
            try {
                // Capture current thread for potential interruption
                session.setAnalysisThread(Thread.currentThread());
                session.setStatus("running");
                session.addLog("INFO", "Starting analysis...");

                // Check if cancelled before starting
                if (session.isCancelled()) {
                    session.addLog("WARNING", "Analysis cancelled before start");
                    return;
                }

                // Build analyzer config using centralized utility parsers
                UnifiedAnalyzer.AnalyzerConfig.Builder configBuilder = UnifiedAnalyzer.AnalyzerConfig.builder()
                    .mode(ModeParser.parse(request.mode()))
                    .baseUrl(request.baseUrl())
                    .authHeader(request.authHeader())
                    .cryptoProtocol(CryptoProtocolParser.parse(request.cryptoProtocol()))
                    .verifySsl(request.verifySsl())
                    .gostPfxPath(request.gostPfxPath())
                    .gostPfxPassword(request.gostPfxPassword())
                    .gostPfxResource(request.gostPfxResource())
                    .verbose(request.verbose())
                    .noFuzzing(request.noFuzzing())
                    .autoAuth(request.autoAuth())
                    .createTestUsers(request.createTestUsers());

                // Configure IP+SNI for GOST TLS hostname bypass
                if (request.serverIp() != null && !request.serverIp().isEmpty() &&
                    request.sniHostname() != null && !request.sniHostname().isEmpty()) {
                    configBuilder
                        .useLowLevelSocket(true)
                        .targetIP(request.serverIp())
                        .sniHostname(request.sniHostname());
                    session.addLog("INFO", "GOST TLS bypass enabled: IP=" + request.serverIp() + ", SNI=" + request.sniHostname());
                }

                if (request.maxParallelScans() != null && request.maxParallelScans() > 0) {
                    configBuilder.maxParallelScans(request.maxParallelScans());
                }

                // Check if Discovery is enabled
                boolean discoveryEnabled = request.enableDiscovery() ||
                    (request.discoveryStrategy() != null && !"none".equalsIgnoreCase(request.discoveryStrategy()));

                // Pass enabled scanners configuration
                // IMPORTANT: If enabledScanners is provided (not null), always use it - even if empty!
                // Empty list = disable all scanners (e.g., for Discovery-only mode)
                // Null = not specified, use default behavior (all scanners)
                if (request.enabledScanners() != null) {
                    // User explicitly provided scanner selection (even if empty)
                    configBuilder.enabledScanners(request.enabledScanners());
                    if (request.enabledScanners().isEmpty()) {
                        session.addLog("INFO", "All vulnerability scanners disabled (Discovery-only mode)");
                    } else {
                        session.addLog("INFO", "Enabled " + request.enabledScanners().size() + " scanner(s): " +
                            String.join(", ", request.enabledScanners()));
                    }
                }
                // else: enabledScanners is null - use all scanners (default behavior)

                // Configure scan intensity
                if (request.scanIntensity() != null && !request.scanIntensity().isEmpty()) {
                    configBuilder.scanIntensity(request.scanIntensity());
                    session.addLog("INFO", "Scan intensity set to: " + request.scanIntensity());
                }

                // Configure custom request delay (overrides intensity default)
                if (request.requestDelayMs() != null && request.requestDelayMs() >= 0) {
                    configBuilder.requestDelayMs(request.requestDelayMs());
                    session.addLog("INFO", "Custom request delay: " + request.requestDelayMs() + "ms");
                }

                // Configure test users for BOLA/privilege testing
                if (request.testUsers() != null && !request.testUsers().isEmpty()) {
                    List<active.auth.AuthCredentials> authCredentials = request.testUsers().stream()
                        .map(this::convertToAuthCredentials)
                        .collect(Collectors.toList());
                    configBuilder.testUsers(authCredentials);
                    session.addLog("INFO", "Configured " + authCredentials.size() + " test user(s) for privilege escalation testing");
                }

                // Configure endpoint discovery
                if (discoveryEnabled) {
                    String strategy = request.discoveryStrategy() != null ? request.discoveryStrategy() : "hybrid";
                    configBuilder
                        .enableDiscovery(true)
                        .discoveryStrategy(strategy)
                        .discoveryMaxDepth(request.discoveryMaxDepth() != null ? request.discoveryMaxDepth() : 5)
                        .discoveryMaxRequests(request.discoveryMaxRequests() != null ? request.discoveryMaxRequests() : 1000)
                        .discoveryFastCancel(request.discoveryFastCancel())
                        .wordlistDir(request.wordlistDir() != null ? request.wordlistDir() : "./wordlists");

                    session.addLog("INFO", "Endpoint Discovery enabled:");
                    session.addLog("INFO", "  Strategy: " + strategy);
                    session.addLog("INFO", "  Max Depth: " + (request.discoveryMaxDepth() != null ? request.discoveryMaxDepth() : 5));
                    session.addLog("INFO", "  Max Requests: " + (request.discoveryMaxRequests() != null ? request.discoveryMaxRequests() : 1000));
                    session.addLog("INFO", "  Fast Cancel: " + request.discoveryFastCancel());
                }

                // Set progress listener to update session state
                configBuilder.progressListener(new AnalysisProgressListener() {
                    @Override
                    public void onLog(String level, String message) {
                        session.addLog(level, message);

                        // Extract detailed info from messages
                        if (message.contains("Scanning endpoint") && message.contains("/")) {
                            // Extract endpoint info from "Scanning endpoint 3/15: GET /api/accounts"
                            String[] parts = message.split(":", 2);
                            if (parts.length > 1) {
                                session.setCurrentEndpoint(parts[1].trim());
                            }
                        } else if (message.contains("Running scanner") && message.contains(":")) {
                            // Extract scanner info from "  Running scanner 2/7: BolaScanner"
                            String[] parts = message.split(":", 2);
                            if (parts.length > 1) {
                                session.setCurrentScanner(parts[1].trim());
                            }
                        } else if (message.contains("vulnerabilities so far") || message.contains("vulnerability(ies)")) {
                            // Extract vulnerability count
                            try {
                                String[] words = message.split("\\s+");
                                for (int i = 0; i < words.length - 1; i++) {
                                    if (words[i+1].startsWith("vulnerabilit")) {
                                        session.setTotalVulnerabilitiesFound(Integer.parseInt(words[i]));
                                        break;
                                    }
                                }
                            } catch (Exception ignored) {}
                        }
                    }

                    @Override
                    public void onPhaseChange(String phase, int totalSteps) {
                        session.setCurrentPhase(phase);
                        session.setTotalSteps(totalSteps);
                        session.setCurrentStep(0);
                        session.addLog("INFO", "Starting phase: " + phase);
                    }

                    @Override
                    public void onStepComplete(int stepNumber, String message) {
                        session.setCurrentStep(stepNumber);
                        if (message != null && !message.isEmpty()) {
                            session.addLog("INFO", message);
                        }
                    }
                });

                UnifiedAnalyzer.AnalyzerConfig config = configBuilder.build();

                // Perform analysis
                UnifiedAnalyzer analyzer = new UnifiedAnalyzer(config);

                // Clean up the spec location using centralized utility
                String specLocation = StringUtils.cleanSpecLocation(request.specLocation());

                // Check if cancelled before starting main analysis
                if (session.isCancelled() || Thread.currentThread().isInterrupted()) {
                    session.addLog("WARNING", "Analysis cancelled before starting main analysis");
                    return;
                }

                session.addLog("INFO", "Loading specification: " + specLocation);
                AnalysisReport report = analyzer.analyze(specLocation);

                // Check if cancelled after analysis
                if (session.isCancelled() || Thread.currentThread().isInterrupted()) {
                    session.addLog("WARNING", "Analysis cancelled after completion");
                    return;
                }

                session.setReport(report);
                session.setStatus("completed");
                session.addLog("INFO", "Analysis completed successfully");

            } catch (Exception e) {
                // Check if this is a cancellation (either explicit or via thread interruption)
                if (session.isCancelled() || Thread.currentThread().isInterrupted()) {
                    session.setStatus("cancelled");
                    session.addLog("WARNING", "Analysis was cancelled by user");
                    logger.info("Analysis cancelled for session {}", sessionId);
                    if (Thread.currentThread().isInterrupted()) {
                        Thread.currentThread().interrupt(); // Restore interrupt status
                    }
                } else {
                    session.setStatus("failed");
                    session.addLog("ERROR", "Analysis failed: " + e.getMessage());
                    logger.error("Analysis failed for session {}", sessionId, e);
                }
            }
        }, executorService);

        // Store the task for potential cancellation
        session.setAnalysisTask(analysisTask);

        return sessionId;
    }

    /**
     * Получение статуса сессии анализа.
     */
    public Optional<AnalysisSession> getSession(String sessionId) {
        return Optional.ofNullable(activeSessions.get(sessionId));
    }

    /**
     * Отмена сессии анализа.
     */
    public boolean cancelAnalysis(String sessionId) {
        AnalysisSession session = activeSessions.get(sessionId);
        if (session != null) {
            logger.info("Cancelling analysis for session {}", sessionId);

            // Mark as cancelled
            session.setStatus("cancelled");
            session.addLog("WARNING", "Cancellation requested by user");

            // Try to cancel the CompletableFuture
            CompletableFuture<Void> task = session.getAnalysisTask();
            if (task != null && !task.isDone()) {
                boolean cancelled = task.cancel(true);
                logger.info("CompletableFuture cancel result: {}", cancelled);
            }

            // Try to interrupt the thread
            Thread thread = session.getAnalysisThread();
            if (thread != null && thread.isAlive()) {
                logger.info("Interrupting analysis thread: {}", thread.getName());
                thread.interrupt();
            }

            return true;
        }
        return false;
    }

    /**
     * Запуск новой сессии анализа AsyncAPI.
     *
     * @param request параметры запроса на анализ AsyncAPI
     * @return sessionId идентификатор созданной сессии
     */
    public String startAsyncAnalysis(AsyncAnalysisRequest request) {
        String sessionId = UUID.randomUUID().toString();

        AnalysisSession session = new AnalysisSession(sessionId);
        session.setWebSocketHandler(webSocketHandler);
        activeSessions.put(sessionId, session);

        // Run analysis in background
        CompletableFuture<Void> analysisTask = CompletableFuture.runAsync(() -> {
            try {
                // Capture current thread for potential interruption
                session.setAnalysisThread(Thread.currentThread());
                session.setStatus("running");
                session.addLog("INFO", "Starting AsyncAPI analysis...");

                // Check if cancelled before starting
                if (session.isCancelled()) {
                    session.addLog("WARNING", "Analysis cancelled before start");
                    return;
                }

                // Load AsyncAPI specification
                String specLocation = StringUtils.cleanSpecLocation(request.specLocation());
                session.addLog("INFO", "Loading AsyncAPI specification: " + specLocation);

                AsyncApiLoader loader = new AsyncApiLoader();
                AsyncApiLoader.LoadResult loadResult = loader.load(specLocation);

                if (!loadResult.isSuccessful()) {
                    session.addLog("ERROR", "Failed to load AsyncAPI spec: " +
                        String.join(", ", loadResult.getMessages()));
                    session.setStatus("failed");
                    return;
                }

                JsonNode asyncApiNode = loadResult.getAsyncApiNode();
                session.addLog("INFO", "AsyncAPI specification loaded successfully");

                // Parse channels and servers
                AsyncSpecNormalizer normalizer = new AsyncSpecNormalizer();
                List<ChannelSpec> channels = normalizer.normalize(asyncApiNode);
                Map<String, ServerSpec> servers = normalizer.extractServers(asyncApiNode);

                session.addLog("INFO", "Found " + channels.size() + " channel(s) and " + servers.size() + " server(s)");

                // Select server if specified
                if (request.selectedServer() != null && !request.selectedServer().isEmpty()) {
                    ServerSpec selectedServer = servers.get(request.selectedServer());
                    if (selectedServer != null) {
                        servers = Map.of(request.selectedServer(), selectedServer);
                        session.addLog("INFO", "Using selected server: " + request.selectedServer());
                    } else {
                        session.addLog("WARNING", "Selected server not found: " + request.selectedServer());
                    }
                }

                // Check mode
                String mode = request.mode() != null ? request.mode() : "static";
                session.addLog("INFO", "Analysis mode: " + mode);

                // List to collect all findings
                List<model.ValidationFinding> allFindings = new ArrayList<>();
                long staticDurationMs = 0;

                // Perform static analysis for "static" or "both" modes
                if ("static".equals(mode) || "both".equals(mode)) {
                    session.setCurrentPhase("static-analysis");
                    session.addLog("INFO", "Starting static AsyncAPI analysis...");

                    long staticStartTime = System.currentTimeMillis();

                    // Run AsyncSecurityValidator
                    session.addLog("INFO", "Running security validation...");
                    AsyncSecurityValidator securityValidator = new AsyncSecurityValidator(asyncApiNode);
                    List<model.ValidationFinding> securityFindings = securityValidator.validate();
                    session.addLog("INFO", "Security validation found " + securityFindings.size() + " issue(s)");
                    allFindings.addAll(securityFindings);

                    // Run AsyncContractValidator
                    session.addLog("INFO", "Running contract validation...");
                    AsyncContractValidator contractValidator = new AsyncContractValidator(asyncApiNode);
                    List<model.ValidationFinding> contractFindings = contractValidator.validate();
                    session.addLog("INFO", "Contract validation found " + contractFindings.size() + " issue(s)");
                    allFindings.addAll(contractFindings);

                    staticDurationMs = System.currentTimeMillis() - staticStartTime;
                    session.addLog("INFO", "Static analysis completed in " + staticDurationMs + "ms. Total issues: " + allFindings.size());
                    session.setTotalVulnerabilitiesFound(allFindings.size());

                    // If only static mode, create report now
                    if ("static".equals(mode)) {
                        // Extract title from AsyncAPI spec
                        String specTitle = "AsyncAPI Specification";
                        if (asyncApiNode.has("info") && asyncApiNode.get("info").has("title")) {
                            specTitle = asyncApiNode.get("info").get("title").asText();
                        }

                        java.time.Instant now = java.time.Instant.now();
                        java.time.Instant startTime = now.minusMillis(staticDurationMs);

                        // Create static result with findings
                        AnalysisReport.StaticAnalysisResult staticResult = new AnalysisReport.StaticAnalysisResult(
                            List.of("Static AsyncAPI analysis completed"),
                            allFindings,
                            null
                        );

                        // Build the report
                        AnalysisReport report = AnalysisReport.builder()
                            .specLocation(specLocation)
                            .specTitle(specTitle)
                            .startTime(startTime)
                            .endTime(now)
                            .mode(AnalysisReport.AnalysisMode.STATIC_ONLY)
                            .staticResult(staticResult)
                            .build();

                        session.setReport(report);
                    }
                }

                if ("active".equals(mode) || "both".equals(mode)) {
                    // Perform active analysis
                    session.setCurrentPhase("active-analysis");
                    session.addLog("INFO", "Starting active AsyncAPI analysis...");

                    // Build scan intensity
                    ScanIntensity intensity = ScanIntensity.MEDIUM;
                    if (request.scanIntensity() != null) {
                        try {
                            intensity = ScanIntensity.valueOf(request.scanIntensity().toUpperCase());
                        } catch (IllegalArgumentException e) {
                            session.addLog("WARNING", "Unknown scan intensity: " + request.scanIntensity() + ", using MEDIUM");
                        }
                    }

                    // Get first server URL for scan context base URL
                    String baseUrl = servers.values().stream()
                        .findFirst()
                        .map(ServerSpec::getUrl)
                        .orElse("async://localhost");

                    // Build scan context
                    ScanContext.Builder contextBuilder = ScanContext.builder()
                        .baseUrl(baseUrl)
                        .scanIntensity(intensity);

                    // Add credentials if provided
                    if (request.credentials() != null && !request.credentials().isEmpty()) {
                        session.addLog("INFO", "Configuring authentication credentials");
                        Map<String, String> creds = request.credentials();
                        if (creds.containsKey("username")) {
                            contextBuilder.addAuthHeader("X-Username", creds.get("username"));
                        }
                        if (creds.containsKey("password")) {
                            contextBuilder.addAuthHeader("X-Password", creds.get("password"));
                        }
                        if (creds.containsKey("apiKey")) {
                            contextBuilder.addAuthHeader("X-Api-Key", creds.get("apiKey"));
                        }
                    }

                    ScanContext scanContext = contextBuilder.build();

                    // Build AsyncAnalysisEngine
                    AsyncAnalysisEngine.Builder engineBuilder = new AsyncAnalysisEngine.Builder()
                        .withScanContext(scanContext)
                        .withPluginsDirectory("plugins")
                        .withAutoDiscoverPlugins(true);

                    if (request.maxParallelScans() != null && request.maxParallelScans() > 0) {
                        engineBuilder.withThreadPoolSize(request.maxParallelScans());
                    }

                    AsyncAnalysisEngine engine = engineBuilder.build();

                    try {
                        // Check if cancelled before main analysis
                        if (session.isCancelled() || Thread.currentThread().isInterrupted()) {
                            session.addLog("WARNING", "Analysis cancelled before execution");
                            return;
                        }

                        session.setTotalSteps(channels.size());
                        session.addLog("INFO", "Analyzing " + channels.size() + " channel(s)...");

                        // Perform analysis
                        AsyncAnalysisReport asyncReport = engine.analyze(channels, servers);

                        session.addLog("INFO", "Active analysis completed. Found " +
                            asyncReport.getTotalVulnerabilities() + " vulnerability(ies)");

                        // For "both" mode, combine static and active findings
                        int totalVulns = asyncReport.getTotalVulnerabilities() + allFindings.size();
                        session.setTotalVulnerabilitiesFound(totalVulns);

                        // Convert AsyncAnalysisReport to standard AnalysisReport for compatibility
                        AnalysisReport report = convertAsyncReportToStandard(asyncReport, asyncApiNode, specLocation, allFindings);
                        session.setReport(report);

                    } finally {
                        engine.shutdown();
                    }
                }

                // Check if cancelled after analysis
                if (session.isCancelled() || Thread.currentThread().isInterrupted()) {
                    session.addLog("WARNING", "Analysis cancelled after completion");
                    return;
                }

                session.setStatus("completed");
                session.addLog("INFO", "AsyncAPI analysis completed successfully");

            } catch (Exception e) {
                // Check if this is a cancellation
                if (session.isCancelled() || Thread.currentThread().isInterrupted()) {
                    session.setStatus("cancelled");
                    session.addLog("WARNING", "Analysis was cancelled by user");
                    logger.info("AsyncAPI analysis cancelled for session {}", sessionId);
                    if (Thread.currentThread().isInterrupted()) {
                        Thread.currentThread().interrupt();
                    }
                } else {
                    session.setStatus("failed");
                    session.addLog("ERROR", "AsyncAPI analysis failed: " + e.getMessage());
                    logger.error("AsyncAPI analysis failed for session {}", sessionId, e);
                }
            }
        }, executorService);

        // Store the task for potential cancellation
        session.setAnalysisTask(analysisTask);

        return sessionId;
    }

    /**
     * Конвертирует AsyncAnalysisReport в стандартный AnalysisReport для совместимости с WebUI.
     *
     * @param asyncReport отчет об активном анализе AsyncAPI
     * @param asyncApiNode JSON-узел AsyncAPI спецификации
     * @param specLocation путь к спецификации
     * @param staticFindings дополнительные findings от статического анализа (может быть пустым)
     */
    private AnalysisReport convertAsyncReportToStandard(AsyncAnalysisReport asyncReport, JsonNode asyncApiNode,
                                                         String specLocation, List<model.ValidationFinding> staticFindings) {
        // Extract title from AsyncAPI spec
        String specTitle = "AsyncAPI Specification";
        if (asyncApiNode.has("info")) {
            JsonNode infoNode = asyncApiNode.get("info");
            if (infoNode.has("title")) {
                specTitle = infoNode.get("title").asText();
            }
        }

        java.time.Instant now = java.time.Instant.now();
        java.time.Instant startTime = now.minusMillis(asyncReport.getDurationMs());

        // Create static result with ONLY static findings (not mixed with active)
        AnalysisReport.StaticAnalysisResult staticResult = null;
        if (!staticFindings.isEmpty()) {
            staticResult = new AnalysisReport.StaticAnalysisResult(
                List.of("AsyncAPI static analysis completed"),
                staticFindings,
                null
            );
        }

        // Convert active findings to VulnerabilityReport format for activeResult
        AnalysisReport.ActiveAnalysisResult activeResult = null;
        if (!asyncReport.getScanResults().isEmpty()) {
            List<active.model.VulnerabilityReport> activeVulnerabilities = new ArrayList<>();

            asyncReport.getScanResults().forEach(result -> {
                result.getVulnerabilities().forEach(vuln -> {
                    // Build path from protocol metadata
                    String path = buildVulnerabilityPath(vuln);
                    String method = vuln.getOperation() != null
                        ? vuln.getOperation().getOperationType().getValue().toUpperCase()
                        : "ASYNC";

                    // Create ApiEndpoint for proper frontend grouping
                    active.model.ApiEndpoint endpoint = active.model.ApiEndpoint.builder()
                        .path(path)
                        .method(method)
                        .build();

                    // Map VulnerabilityType from AsyncVulnerabilityReport
                    active.model.VulnerabilityReport.VulnerabilityType vulnType = mapAsyncVulnType(vuln.getType());

                    // Convert recommendations
                    List<String> recommendations = vuln.getRecommendations().isEmpty()
                        ? List.of("Review the AsyncAPI specification and implement proper security controls")
                        : vuln.getRecommendations();

                    // Build VulnerabilityReport
                    active.model.VulnerabilityReport vulnReport = active.model.VulnerabilityReport.builder()
                        .type(vulnType)
                        .severity(model.Severity.valueOf(vuln.getSeverity().name()))
                        .endpoint(endpoint)
                        .title(vuln.getTitle())
                        .description(vuln.getDescription())
                        .reproductionSteps(vuln.getReproductionSteps())
                        .recommendations(recommendations)
                        .evidence(vuln.getEvidence() != null ? new HashMap<>(vuln.getEvidence()) : Map.of())
                        .build();

                    activeVulnerabilities.add(vulnReport);
                });
            });

            if (!activeVulnerabilities.isEmpty()) {
                // Create EndpointAnalysisResults grouped by endpoint
                Map<String, List<active.model.VulnerabilityReport>> byEndpoint = new LinkedHashMap<>();
                for (active.model.VulnerabilityReport v : activeVulnerabilities) {
                    String key = v.getEndpoint().getMethod() + " " + v.getEndpoint().getPath();
                    byEndpoint.computeIfAbsent(key, k -> new ArrayList<>()).add(v);
                }

                List<ActiveAnalysisEngine.EndpointAnalysisResult> endpointResults = new ArrayList<>();
                for (Map.Entry<String, List<active.model.VulnerabilityReport>> entry : byEndpoint.entrySet()) {
                    List<active.model.VulnerabilityReport> vulns = entry.getValue();
                    if (!vulns.isEmpty()) {
                        active.model.ApiEndpoint endpoint = vulns.get(0).getEndpoint();
                        // Create ScanResult using builder
                        active.scanner.ScanResult scanResult = active.scanner.ScanResult.builder()
                            .scannerId("async-scanner")
                            .endpoint(endpoint)
                            .status(active.scanner.ScanResult.ScanStatus.SUCCESS)
                            .vulnerabilities(vulns)
                            .startTime(startTime)
                            .endTime(now)
                            .build();
                        endpointResults.add(new ActiveAnalysisEngine.EndpointAnalysisResult(
                            endpoint, List.of(scanResult), startTime, now
                        ));
                    }
                }

                ActiveAnalysisEngine.AnalysisReport activeReport =
                    new ActiveAnalysisEngine.AnalysisReport(endpointResults, startTime, now);
                activeResult = new AnalysisReport.ActiveAnalysisResult(activeReport, null);
            }
        }

        // Determine mode based on what results we have
        AnalysisReport.AnalysisMode mode;
        if (staticResult != null && activeResult != null) {
            mode = AnalysisReport.AnalysisMode.COMBINED;
        } else if (activeResult != null) {
            mode = AnalysisReport.AnalysisMode.ACTIVE_ONLY;
        } else {
            mode = AnalysisReport.AnalysisMode.STATIC_ONLY;
        }

        // Build the report using Builder pattern
        AnalysisReport.Builder builder = AnalysisReport.builder()
            .specLocation(specLocation)
            .specTitle(specTitle)
            .startTime(startTime)
            .endTime(now)
            .mode(mode);

        if (staticResult != null) {
            builder.staticResult(staticResult);
        }
        if (activeResult != null) {
            builder.activeResult(activeResult);
        }

        return builder.build();
    }

    /**
     * Maps AsyncVulnerabilityReport.AsyncVulnerabilityType to VulnerabilityReport.VulnerabilityType.
     */
    private active.model.VulnerabilityReport.VulnerabilityType mapAsyncVulnType(
            active.async.AsyncVulnerabilityReport.AsyncVulnerabilityType asyncType) {
        return switch (asyncType) {
            case UNAUTHORIZED_SUBSCRIPTION, UNAUTHORIZED_PUBLISH, WEAK_AUTHENTICATION,
                 MISSING_AUTHORIZATION, EXCESSIVE_PRIVILEGES ->
                    active.model.VulnerabilityReport.VulnerabilityType.BROKEN_AUTHENTICATION;
            case MESSAGE_INJECTION ->
                    active.model.VulnerabilityReport.VulnerabilityType.SQL_INJECTION;
            case TOPIC_ENUMERATION, SENSITIVE_DATA_EXPOSURE ->
                    active.model.VulnerabilityReport.VulnerabilityType.INFORMATION_DISCLOSURE;
            case MESSAGE_REPLAY, MESSAGE_TAMPERING ->
                    active.model.VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION;
            case SCHEMA_VALIDATION_BYPASS ->
                    active.model.VulnerabilityReport.VulnerabilityType.MASS_ASSIGNMENT;
            case POISONED_MESSAGE, DENIAL_OF_SERVICE ->
                    active.model.VulnerabilityReport.VulnerabilityType.UNRESTRICTED_RESOURCE;
            case MISSING_ENCRYPTION ->
                    active.model.VulnerabilityReport.VulnerabilityType.WEAK_CRYPTOGRAPHY;
        };
    }

    /**
     * Builds a path string from AsyncVulnerabilityReport.
     */
    private String buildVulnerabilityPath(active.async.AsyncVulnerabilityReport vuln) {
        StringBuilder path = new StringBuilder();

        if (vuln.getProtocolMetadata() != null) {
            if (vuln.getProtocolMetadata().getChannel() != null) {
                path.append(vuln.getProtocolMetadata().getChannel());
            } else {
                path.append(vuln.getProtocolMetadata().getProtocol()).append("://unknown");
            }
        } else {
            path.append("/async/channel");
        }

        return path.toString();
    }

    /**
     * Преобразование UserCredentials из WebUI в AuthCredentials ядра.
     */
    private active.auth.AuthCredentials convertToAuthCredentials(UserCredentials userCreds) {
        active.auth.AuthCredentials.Builder builder = active.auth.AuthCredentials.builder();

        if (userCreds.username() != null) {
            builder.username(userCreds.username());
        }
        if (userCreds.password() != null) {
            builder.password(userCreds.password());
        }
        if (userCreds.token() != null) {
            builder.token(userCreds.token());
        }

        // Add client credentials as additional headers
        if (userCreds.clientId() != null) {
            builder.addHeader("X-Client-Id", userCreds.clientId());
        }
        if (userCreds.clientSecret() != null) {
            builder.addHeader("X-Client-Secret", userCreds.clientSecret());
        }
        if (userCreds.role() != null) {
            builder.addHeader("X-User-Role", userCreds.role());
        }

        return builder.build();
    }

    private ScannerInfo toScannerInfo(VulnerabilityScanner scanner) {
        String category = categorizeScanner(scanner.getId());
        List<String> vulnTypes = scanner.getDetectedVulnerabilities().stream()
            .map(Enum::name)
            .collect(Collectors.toList());

        // Get localized name and description from plugin message service
        String scannerId = scanner.getId();
        String localizedName = scanner.getName(); // fallback
        String localizedDescription = scanner.getDescription(); // fallback

        try {
            // Get bundle name from mapping
            String bundleName = SCANNER_ID_TO_BUNDLE.get(scannerId);

            if (bundleName != null) {
                // Use scanner's ClassLoader to load .properties files from plugin JARs
                ClassLoader scannerClassLoader = scanner.getClass().getClassLoader();

                logger.info("Loading localization for scanner '{}' using bundle '{}', ClassLoader: {}",
                    scannerId, bundleName, scannerClassLoader.getClass().getName());

                // Check if resource exists
                java.net.URL resourceUrl = scannerClassLoader.getResource(bundleName + ".properties");
                logger.info("Resource URL for {}.properties: {}", bundleName, resourceUrl);

                // Use PluginMessageService to get localized strings
                localizedName = com.apisecurity.analyzer.core.i18n.PluginMessageService.getMessage(
                    bundleName, "scanner.name", scannerClassLoader
                );
                localizedDescription = com.apisecurity.analyzer.core.i18n.PluginMessageService.getMessage(
                    bundleName, "scanner.description", scannerClassLoader
                );

                logger.info("Localized name: '{}', description: '{}'", localizedName, localizedDescription);

                // Check if we got the key back (meaning localization failed)
                if ("scanner.name".equals(localizedName)) {
                    logger.error("Localization failed for scanner '{}': got key back instead of value. Bundle '{}' not found.",
                        scannerId, bundleName);
                }
            } else {
                logger.warn("No bundle mapping found for scanner ID: {}", scannerId);
            }
        } catch (Exception e) {
            // If localization fails, use default name and description from scanner
            logger.error("Failed to load localization for scanner {}: {}", scannerId, e.getMessage(), e);
        }

        return new ScannerInfo(
            scanner.getId(),
            localizedName,
            localizedDescription,
            vulnTypes,
            scanner.getConfig().isEnabled(),
            category
        );
    }

    private String categorizeScanner(String scannerId) {
        if (scannerId.contains("bola") || scannerId.contains("bfla") ||
            scannerId.contains("bopla") || scannerId.contains("auth")) {
            return "Authentication & Authorization";
        } else if (scannerId.contains("injection") || scannerId.contains("sql") ||
                   scannerId.contains("xxe") || scannerId.contains("traversal")) {
            return "Injection Attacks";
        } else if (scannerId.contains("crypto") || scannerId.contains("tls")) {
            return "Cryptography";
        } else if (scannerId.contains("config") || scannerId.contains("inventory")) {
            return "Configuration & Deployment";
        } else if (scannerId.contains("disclosure") || scannerId.contains("ssrf")) {
            return "Information Disclosure";
        } else if (scannerId.contains("flow") || scannerId.contains("resource")) {
            return "Business Logic";
        }
        return "Other";
    }

    /**
     * Отслеживание сессии анализа.
     */
    public static class AnalysisSession {
        private final String sessionId;
        private final List<LogEntry> logs = new CopyOnWriteArrayList<>();
        private volatile String status = "pending"; // pending, running, completed, failed, cancelled
        private volatile AnalysisReport report;
        private volatile int currentStep = 0;
        private volatile int totalSteps = 0;
        private volatile long startTime = 0;
        private volatile String currentPhase = ""; // "parsing", "authentication", "scanning", "analyzing"
        private volatile String currentEndpoint = "";
        private volatile String currentScanner = "";
        private volatile int totalVulnerabilitiesFound = 0;
        private volatile CompletableFuture<Void> analysisTask;
        private volatile Thread analysisThread;
        private AnalysisWebSocketHandler webSocketHandler;

        public AnalysisSession(String sessionId) {
            this.sessionId = sessionId;
        }

        public void setWebSocketHandler(AnalysisWebSocketHandler handler) {
            this.webSocketHandler = handler;
        }

        private void broadcastUpdate() {
            if (webSocketHandler != null) {
                Map<String, Object> update = new HashMap<>();
                update.put("sessionId", sessionId);
                update.put("status", status);
                update.put("logs", new ArrayList<>(logs));
                update.put("report", report);
                update.put("currentStep", currentStep);
                update.put("totalSteps", totalSteps);
                update.put("progressPercentage", getProgressPercentage());
                update.put("estimatedTimeRemaining", getEstimatedTimeRemaining());
                update.put("currentPhase", currentPhase);
                update.put("currentEndpoint", currentEndpoint);
                update.put("currentScanner", currentScanner);
                update.put("totalVulnerabilitiesFound", totalVulnerabilitiesFound);
                webSocketHandler.broadcastUpdate(sessionId, update);
            }
        }

        public String getSessionId() {
            return sessionId;
        }

        public List<LogEntry> getLogs() {
            return new ArrayList<>(logs);
        }

        public void addLog(String level, String message) {
            logs.add(new LogEntry(System.currentTimeMillis(), level, message));
            broadcastUpdate();
        }

        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
            if ("running".equals(status) && startTime == 0) {
                startTime = System.currentTimeMillis();
            }
            broadcastUpdate();
        }

        public AnalysisReport getReport() {
            return report;
        }

        public void setReport(AnalysisReport report) {
            this.report = report;
            broadcastUpdate();
        }

        public int getCurrentStep() {
            return currentStep;
        }

        public void setCurrentStep(int currentStep) {
            this.currentStep = currentStep;
            broadcastUpdate();
        }

        public int getTotalSteps() {
            return totalSteps;
        }

        public void setTotalSteps(int totalSteps) {
            this.totalSteps = totalSteps;
            broadcastUpdate();
        }

        public double getProgressPercentage() {
            if (totalSteps == 0) return 0.0;
            // Return raw percentage - frontend will format with toFixed(1)
            return (currentStep * 100.0) / totalSteps;
        }

        public long getEstimatedTimeRemaining() {
            if (startTime == 0 || currentStep == 0 || totalSteps == 0) return 0;
            long elapsed = System.currentTimeMillis() - startTime;
            long avgTimePerStep = elapsed / currentStep;
            int remainingSteps = totalSteps - currentStep;
            return avgTimePerStep * remainingSteps;
        }

        public String getCurrentPhase() {
            return currentPhase;
        }

        public void setCurrentPhase(String phase) {
            this.currentPhase = phase;
            broadcastUpdate();
        }

        public void incrementStep(String message) {
            currentStep++;
            if (message != null && !message.isEmpty()) {
                addLog("INFO", message);
            } else {
                broadcastUpdate();
            }
        }

        public String getCurrentEndpoint() {
            return currentEndpoint;
        }

        public void setCurrentEndpoint(String endpoint) {
            this.currentEndpoint = endpoint;
            broadcastUpdate();
        }

        public String getCurrentScanner() {
            return currentScanner;
        }

        public void setCurrentScanner(String scanner) {
            this.currentScanner = scanner;
            broadcastUpdate();
        }

        public int getTotalVulnerabilitiesFound() {
            return totalVulnerabilitiesFound;
        }

        public void setTotalVulnerabilitiesFound(int count) {
            this.totalVulnerabilitiesFound = count;
            broadcastUpdate();
        }

        public void setAnalysisTask(CompletableFuture<Void> task) {
            this.analysisTask = task;
        }

        public CompletableFuture<Void> getAnalysisTask() {
            return analysisTask;
        }

        public void setAnalysisThread(Thread thread) {
            this.analysisThread = thread;
        }

        public Thread getAnalysisThread() {
            return analysisThread;
        }

        public boolean isCancelled() {
            return "cancelled".equals(status);
        }
    }

    /**
     * Получение информации об AsyncAPI спецификации.
     * Возвращает список серверов, доступных протоколов и AsyncAPI сканеров.
     * Не выбрасывает исключения - возвращает результат с ошибками валидации если файл невалиден.
     */
    public AsyncApiInfo getAsyncApiInfo(String specLocation) {
        // Получение доступных протоколов из ProtocolRegistry
        ProtocolRegistry protocolRegistry = ProtocolRegistry.getInstance();
        List<String> availableProtocols = new ArrayList<>(protocolRegistry.getRegisteredProtocols());
        Collections.sort(availableProtocols);

        // Получение AsyncAPI сканеров
        AsyncScannerRegistry asyncScannerRegistry = AsyncScannerRegistry.getInstance();
        List<AsyncScannerInfo> asyncScanners = asyncScannerRegistry.getAllScanners().stream()
            .map(scanner -> new AsyncScannerInfo(
                toScannerId(scanner.getName()),
                scanner.getName(),
                scanner.getDescription(),
                scanner.getSupportedProtocols(),
                scanner.isEnabledByDefault()
            ))
            .sorted(Comparator.comparing(AsyncScannerInfo::name))
            .collect(Collectors.toList());

        try {
            // Загрузка AsyncAPI спецификации
            AsyncApiLoader loader = new AsyncApiLoader();
            AsyncApiLoader.LoadResult result = loader.load(specLocation);

            if (!result.isSuccessful()) {
                // Файл не является валидной AsyncAPI спецификацией - возвращаем результат с ошибками
                logger.warn("Invalid AsyncAPI spec at {}: {}", specLocation, result.getMessages());
                return AsyncApiInfo.invalid(result.getMessages(), availableProtocols, asyncScanners);
            }

            JsonNode asyncApiNode = result.getAsyncApiNode();

            // Извлечение серверов
            List<ServerInfo> servers = extractServers(asyncApiNode);

            // Проверка на предупреждения
            if (result.hasMessages()) {
                return AsyncApiInfo.withWarnings(servers, availableProtocols, asyncScanners, result.getMessages());
            }

            return AsyncApiInfo.success(servers, availableProtocols, asyncScanners);

        } catch (Exception e) {
            logger.error("Error loading AsyncAPI info", e);
            return AsyncApiInfo.invalid(
                List.of("Error loading specification: " + e.getMessage()),
                availableProtocols,
                asyncScanners
            );
        }
    }

    /**
     * Извлекает информацию о серверах из AsyncAPI спецификации.
     */
    private List<ServerInfo> extractServers(JsonNode asyncApiNode) {
        List<ServerInfo> servers = new ArrayList<>();

        JsonNode serversNode = asyncApiNode.get("servers");
        if (serversNode == null || !serversNode.isObject()) {
            return servers;
        }

        serversNode.fields().forEachRemaining(entry -> {
            String name = entry.getKey();
            JsonNode serverNode = entry.getValue();

            String url = serverNode.has("url") ? serverNode.get("url").asText() : "";
            String protocol = serverNode.has("protocol") ? serverNode.get("protocol").asText() : "";
            String protocolVersion = serverNode.has("protocolVersion") ?
                serverNode.get("protocolVersion").asText() : "";
            String description = serverNode.has("description") ?
                serverNode.get("description").asText() : "";

            servers.add(new ServerInfo(name, url, protocol, protocolVersion, description));
        });

        return servers;
    }

    /**
     * Конвертирует имя сканера в ID (kebab-case).
     */
    private String toScannerId(String name) {
        return name.toLowerCase()
            .replaceAll("[^a-z0-9]+", "-")
            .replaceAll("^-|-$", "");
    }

    /**
     * Запись лога.
     */
    public record LogEntry(long timestamp, String level, String message) {}
}
