package webui.service;

import active.http.HttpClient;
import active.scanner.ScanIntensity;
import active.scanner.ScannerAutoDiscovery;
import active.scanner.ScannerRegistry;
import active.scanner.VulnerabilityScanner;
import cli.UnifiedAnalyzer;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import report.AnalysisReport;
import util.CryptoProtocolParser;
import util.ModeParser;
import util.StringUtils;
import webui.model.AnalysisRequest;
import webui.model.ScannerInfo;
import webui.model.UserCredentials;
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

    public AnalysisService(AnalysisWebSocketHandler webSocketHandler) {
        this.webSocketHandler = webSocketHandler;
        this.scannerRegistry = new ScannerRegistry();
        // Auto-discover and register all scanners
        int registered = ScannerAutoDiscovery.discoverAndRegister(scannerRegistry);
        logger.info("Registered {} scanners", registered);
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
        CompletableFuture.runAsync(() -> {
            try {
                session.setStatus("running");
                session.addLog("INFO", "Starting analysis...");

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

                if (request.maxParallelScans() != null && request.maxParallelScans() > 0) {
                    configBuilder.maxParallelScans(request.maxParallelScans());
                }

                // Pass enabled scanners configuration
                if (request.enabledScanners() != null && !request.enabledScanners().isEmpty()) {
                    configBuilder.enabledScanners(request.enabledScanners());
                }

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

                // Set progress listener to update session state
                configBuilder.progressListener(new cli.AnalysisProgressListener() {
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

                session.addLog("INFO", "Loading specification: " + specLocation);
                AnalysisReport report = analyzer.analyze(specLocation);

                session.setReport(report);
                session.setStatus("completed");
                session.addLog("INFO", "Analysis completed successfully");

            } catch (Exception e) {
                session.setStatus("failed");
                session.addLog("ERROR", "Analysis failed: " + e.getMessage());
                logger.error("Analysis failed for session {}", sessionId, e);
            }
        }, executorService);

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
            session.setStatus("cancelled");
            return true;
        }
        return false;
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

        return new ScannerInfo(
            scanner.getId(),
            scanner.getName(),
            scanner.getDescription(),
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

        public int getProgressPercentage() {
            if (totalSteps == 0) return 0;
            return (int) ((currentStep * 100.0) / totalSteps);
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
    }

    /**
     * Запись лога.
     */
    public record LogEntry(long timestamp, String level, String message) {}
}
