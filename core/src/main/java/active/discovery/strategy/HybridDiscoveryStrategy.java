package active.discovery.strategy;

import active.discovery.ResponseAnalyzer;
import active.discovery.WordlistManager;
import active.discovery.model.DiscoveryConfig;
import active.discovery.model.DiscoveryResult;
import active.discovery.model.PathNode;
import active.http.HttpClient;
import active.model.AnalysisProgressListener;

import java.util.*;
import java.util.logging.Logger;

/**
 * Гибридная стратегия обнаружения (Hybrid).
 * Комбинирует Top-Down и Bottom-Up подходы для максимального покрытия.
 *
 * <p>Алгоритм:
 * <ol>
 *   <li>Фаза 1: Top-Down для первых 2-3 уровней (широкий поиск)</li>
 *   <li>Фаза 2: Bottom-Up от найденных и документированных эндпоинтов (глубокий поиск)</li>
 *   <li>Объединение результатов с дедупликацией</li>
 * </ol>
 *
 * <p>Преимущества:
 * <ul>
 *   <li>Top-Down находит скрытые версии API, админские панели на верхних уровнях</li>
 *   <li>Bottom-Up находит скрытые действия над ресурсами на глубоких уровнях</li>
 *   <li>Более эффективен чем каждая стратегия по отдельности</li>
 * </ul>
 */
public class HybridDiscoveryStrategy implements DiscoveryStrategy {
    private static final Logger logger = Logger.getLogger(HybridDiscoveryStrategy.class.getName());

    private final TopDownDiscoveryStrategy topDownStrategy;
    private final BottomUpDiscoveryStrategy bottomUpStrategy;

    public HybridDiscoveryStrategy() {
        this.topDownStrategy = new TopDownDiscoveryStrategy();
        this.bottomUpStrategy = new BottomUpDiscoveryStrategy();
    }

    @Override
    public String getName() {
        return "Hybrid";
    }

    @Override
    public String getDescription() {
        return "Combines Top-Down (shallow) and Bottom-Up (deep) strategies for comprehensive coverage";
    }

    @Override
    public List<DiscoveryResult> discover(
            PathNode root,
            String baseUrl,
            HttpClient httpClient,
            WordlistManager wordlistManager,
            ResponseAnalyzer responseAnalyzer,
            DiscoveryConfig config,
            AnalysisProgressListener progressListener) {

        logger.info("Starting Hybrid discovery (Top-Down + Bottom-Up)");
        progressListener.onLog("INFO", "Discovery: Starting Hybrid strategy (Top-Down + Bottom-Up)");

        List<DiscoveryResult> allResults = new ArrayList<>();

        // Phase 1: Top-Down for first 2-3 levels (broad search)
        int topDownMaxDepth = Math.min(3, config.getMaxDepth());
        int topDownMaxRequests = config.getMaxTotalRequests() / 2;

        logger.info("Phase 1: Top-Down discovery (max depth: " + topDownMaxDepth +
                   ", max requests: " + topDownMaxRequests + ")");
        progressListener.onLog("INFO", "Discovery: Phase 1 - Top-Down (max depth: " + topDownMaxDepth + ")");

        DiscoveryConfig topDownConfig = DiscoveryConfig.builder()
            .strategy(DiscoveryConfig.DiscoveryStrategy.TOP_DOWN)
            .maxDepth(topDownMaxDepth)
            .maxRequestsPerLevel(config.getMaxRequestsPerLevel())
            .maxTotalRequests(topDownMaxRequests)
            .requestDelayMs(config.getRequestDelayMs())
            .adaptiveDelay(config.isAdaptiveDelay())
            .fastCancel(false) // Don't cancel in phase 1, continue to phase 2
            .cacheResults(config.isCacheResults())
            .excludePatterns(config.getExcludePatterns())
            .interestingStatusCodes(config.getInterestingStatusCodes())
            .wordlistDirectory(config.getWordlistDirectory())
            .enabledWordlists(config.getEnabledWordlists())
            .parallelism(config.getParallelism())
            .verbose(config.isVerbose())
            .build();

        List<DiscoveryResult> topDownResults = topDownStrategy.discover(
            root, baseUrl, httpClient, wordlistManager, responseAnalyzer, topDownConfig, progressListener);

        allResults.addAll(topDownResults);

        logger.info("Phase 1 completed: found " + topDownResults.size() + " undocumented endpoints");
        progressListener.onLog("INFO", "Discovery: Phase 1 completed - " + topDownResults.size() + " endpoints found");

        // Check for fast cancel after phase 1
        if (config.isFastCancel() && hasDangerousFindings(topDownResults)) {
            logger.warning("Fast cancel triggered during Top-Down phase");
            progressListener.onLog("WARNING", "⚠ Fast cancel triggered - dangerous endpoint found in Phase 1");
            return markAsHybrid(allResults);
        }

        // Phase 2: Bottom-Up for deeper exploration
        int bottomUpMaxRequests = config.getMaxTotalRequests() - topDownMaxRequests;

        logger.info("Phase 2: Bottom-Up discovery (max depth: " + config.getMaxDepth() +
                   ", max requests: " + bottomUpMaxRequests + ")");
        progressListener.onLog("INFO", "Discovery: Phase 2 - Bottom-Up (max depth: " + config.getMaxDepth() + ")");

        DiscoveryConfig bottomUpConfig = DiscoveryConfig.builder()
            .strategy(DiscoveryConfig.DiscoveryStrategy.BOTTOM_UP)
            .maxDepth(config.getMaxDepth())
            .maxRequestsPerLevel(config.getMaxRequestsPerLevel())
            .maxTotalRequests(bottomUpMaxRequests)
            .requestDelayMs(config.getRequestDelayMs())
            .adaptiveDelay(config.isAdaptiveDelay())
            .fastCancel(config.isFastCancel())
            .cacheResults(config.isCacheResults())
            .excludePatterns(config.getExcludePatterns())
            .interestingStatusCodes(config.getInterestingStatusCodes())
            .wordlistDirectory(config.getWordlistDirectory())
            .enabledWordlists(config.getEnabledWordlists())
            .parallelism(config.getParallelism())
            .verbose(config.isVerbose())
            .build();

        List<DiscoveryResult> bottomUpResults = bottomUpStrategy.discover(
            root, baseUrl, httpClient, wordlistManager, responseAnalyzer, bottomUpConfig, progressListener);

        allResults.addAll(bottomUpResults);

        logger.info("Phase 2 completed: found " + bottomUpResults.size() + " undocumented endpoints");
        progressListener.onLog("INFO", "Discovery: Phase 2 completed - " + bottomUpResults.size() + " endpoints found");

        // Deduplicate and mark as hybrid
        List<DiscoveryResult> deduplicatedResults = deduplicateResults(allResults);
        List<DiscoveryResult> hybridResults = markAsHybrid(deduplicatedResults);

        logger.info("Hybrid discovery completed: " + hybridResults.size() +
                   " unique undocumented endpoints (Top-Down: " + topDownResults.size() +
                   ", Bottom-Up: " + bottomUpResults.size() + ")");
        progressListener.onLog("INFO", "Discovery: Hybrid strategy completed - " + hybridResults.size() +
            " unique endpoints (Phase 1: " + topDownResults.size() + ", Phase 2: " + bottomUpResults.size() + ")");

        return hybridResults;
    }

    /**
     * Проверяет наличие опасных находок.
     */
    private boolean hasDangerousFindings(List<DiscoveryResult> results) {
        return results.stream().anyMatch(DiscoveryResult::isDangerous);
    }

    /**
     * Удаляет дубликаты из результатов.
     */
    private List<DiscoveryResult> deduplicateResults(List<DiscoveryResult> results) {
        Map<String, DiscoveryResult> uniqueResults = new LinkedHashMap<>();

        for (DiscoveryResult result : results) {
            String key = result.getEndpoint().getMethod() + ":" + result.getEndpoint().getPath();

            // Keep result with higher severity if duplicate
            if (!uniqueResults.containsKey(key) ||
                result.getSeverity().ordinal() > uniqueResults.get(key).getSeverity().ordinal()) {
                uniqueResults.put(key, result);
            }
        }

        return new ArrayList<>(uniqueResults.values());
    }

    /**
     * Помечает результаты как обнаруженные гибридной стратегией.
     */
    private List<DiscoveryResult> markAsHybrid(List<DiscoveryResult> results) {
        List<DiscoveryResult> hybridResults = new ArrayList<>();

        for (DiscoveryResult result : results) {
            // Create new result with HYBRID method
            DiscoveryResult hybridResult = DiscoveryResult.builder()
                .endpoint(result.getEndpoint())
                .statusCode(result.getStatusCode())
                .responseBody(result.getResponseBody())
                .responseHeaders(result.getResponseHeaders())
                .responseTimeMs(result.getResponseTimeMs())
                .discoveryMethod(DiscoveryResult.DiscoveryMethod.HYBRID)
                .severity(result.getSeverity())
                .reason(result.getReason())
                .discoveredAt(result.getDiscoveredAt())
                .metadata(result.getMetadata())
                .addMetadata("originalMethod", result.getDiscoveryMethod().name())
                .build();

            hybridResults.add(hybridResult);
        }

        return hybridResults;
    }
}
