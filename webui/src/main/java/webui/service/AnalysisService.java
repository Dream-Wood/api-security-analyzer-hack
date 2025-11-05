package webui.service;

import active.http.HttpClient;
import active.scanner.ScannerAutoDiscovery;
import active.scanner.ScannerRegistry;
import active.scanner.VulnerabilityScanner;
import cli.UnifiedAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import report.AnalysisReport;
import webui.model.AnalysisRequest;
import webui.model.ScannerInfo;

import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Service for managing security analysis operations.
 */
@Service
public class AnalysisService {
    private static final Logger logger = LoggerFactory.getLogger(AnalysisService.class);

    private final ScannerRegistry scannerRegistry;
    private final Map<String, AnalysisSession> activeSessions = new ConcurrentHashMap<>();
    private final ExecutorService executorService = Executors.newCachedThreadPool();

    public AnalysisService() {
        this.scannerRegistry = new ScannerRegistry();
        // Auto-discover and register all scanners
        int registered = ScannerAutoDiscovery.discoverAndRegister(scannerRegistry);
        logger.info("Registered {} scanners", registered);
    }

    /**
     * Get information about all available scanners.
     */
    public List<ScannerInfo> getAvailableScanners() {
        return scannerRegistry.getAllScanners().stream()
            .map(this::toScannerInfo)
            .sorted(Comparator.comparing(ScannerInfo::category).thenComparing(ScannerInfo::name))
            .collect(Collectors.toList());
    }

    /**
     * Start a new analysis session.
     */
    public String startAnalysis(AnalysisRequest request) {
        String sessionId = UUID.randomUUID().toString();

        AnalysisSession session = new AnalysisSession(sessionId);
        activeSessions.put(sessionId, session);

        // Run analysis in background
        CompletableFuture.runAsync(() -> {
            try {
                session.setStatus("running");
                session.addLog("INFO", "Starting analysis...");

                // Build analyzer config
                UnifiedAnalyzer.AnalyzerConfig.Builder configBuilder = UnifiedAnalyzer.AnalyzerConfig.builder()
                    .mode(parseMode(request.mode()))
                    .baseUrl(request.baseUrl())
                    .authHeader(request.authHeader())
                    .cryptoProtocol(parseCryptoProtocol(request.cryptoProtocol()))
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

                UnifiedAnalyzer.AnalyzerConfig config = configBuilder.build();

                // Perform analysis
                UnifiedAnalyzer analyzer = new UnifiedAnalyzer(config);

                // Clean up the spec location (remove quotes if present)
                String specLocation = cleanSpecLocation(request.specLocation());

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
     * Get the status of an analysis session.
     */
    public Optional<AnalysisSession> getSession(String sessionId) {
        return Optional.ofNullable(activeSessions.get(sessionId));
    }

    /**
     * Cancel an analysis session.
     */
    public boolean cancelAnalysis(String sessionId) {
        AnalysisSession session = activeSessions.get(sessionId);
        if (session != null) {
            session.setStatus("cancelled");
            return true;
        }
        return false;
    }

    private void configureScanners(List<String> enabledScannerIds) {
        if (enabledScannerIds == null || enabledScannerIds.isEmpty()) {
            // Enable all scanners by default
            return;
        }

        Set<String> enabledSet = new HashSet<>(enabledScannerIds);
        for (VulnerabilityScanner scanner : scannerRegistry.getAllScanners()) {
            boolean shouldEnable = enabledSet.contains(scanner.getId());
            // Create new config with enabled/disabled flag
            active.scanner.ScannerConfig newConfig = active.scanner.ScannerConfig.builder()
                .enabled(shouldEnable)
                .maxTestsPerEndpoint(scanner.getConfig().getMaxTestsPerEndpoint())
                .timeoutSeconds(scanner.getConfig().getTimeoutSeconds())
                .build();
            scanner.setConfig(newConfig);
        }
    }

    private AnalysisReport.AnalysisMode parseMode(String mode) {
        if (mode == null || mode.equalsIgnoreCase("static")) {
            return AnalysisReport.AnalysisMode.STATIC_ONLY;
        } else if (mode.equalsIgnoreCase("active")) {
            return AnalysisReport.AnalysisMode.ACTIVE_ONLY;
        } else if (mode.equalsIgnoreCase("both") || mode.equalsIgnoreCase("combined")) {
            return AnalysisReport.AnalysisMode.COMBINED;
        } else if (mode.equalsIgnoreCase("contract")) {
            return AnalysisReport.AnalysisMode.CONTRACT;
        } else if (mode.equalsIgnoreCase("full") || mode.equalsIgnoreCase("all")) {
            return AnalysisReport.AnalysisMode.FULL;
        }
        return AnalysisReport.AnalysisMode.STATIC_ONLY;
    }

    private HttpClient.CryptoProtocol parseCryptoProtocol(String protocol) {
        if (protocol == null || protocol.equalsIgnoreCase("standard")) {
            return HttpClient.CryptoProtocol.STANDARD_TLS;
        } else if (protocol.equalsIgnoreCase("gost") || protocol.equalsIgnoreCase("cryptopro")) {
            return HttpClient.CryptoProtocol.CRYPTOPRO_JCSP;
        }
        return HttpClient.CryptoProtocol.STANDARD_TLS;
    }

    private String cleanSpecLocation(String location) {
        if (location == null) {
            return null;
        }
        // Remove surrounding quotes if present
        String cleaned = location.trim();
        if (cleaned.startsWith("\"") && cleaned.endsWith("\"")) {
            cleaned = cleaned.substring(1, cleaned.length() - 1);
        }
        if (cleaned.startsWith("'") && cleaned.endsWith("'")) {
            cleaned = cleaned.substring(1, cleaned.length() - 1);
        }
        return cleaned;
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
     * Analysis session tracking.
     */
    public static class AnalysisSession {
        private final String sessionId;
        private final List<LogEntry> logs = new CopyOnWriteArrayList<>();
        private volatile String status = "pending"; // pending, running, completed, failed, cancelled
        private volatile AnalysisReport report;

        public AnalysisSession(String sessionId) {
            this.sessionId = sessionId;
        }

        public String getSessionId() {
            return sessionId;
        }

        public List<LogEntry> getLogs() {
            return new ArrayList<>(logs);
        }

        public void addLog(String level, String message) {
            logs.add(new LogEntry(System.currentTimeMillis(), level, message));
        }

        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }

        public AnalysisReport getReport() {
            return report;
        }

        public void setReport(AnalysisReport report) {
            this.report = report;
        }
    }

    /**
     * Log entry.
     */
    public record LogEntry(long timestamp, String level, String message) {}
}
