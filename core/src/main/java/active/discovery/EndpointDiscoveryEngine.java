package active.discovery;

import active.discovery.model.*;
import active.discovery.strategy.*;
import active.http.HttpClient;
import active.model.AnalysisProgressListener;
import model.OperationSpec;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Главный движок для обнаружения незадокументированных API эндпоинтов.
 * Координирует работу всех компонентов discovery модуля.
 *
 * <p>Основные возможности:
 * <ul>
 *   <li>Построение дерева путей из спецификации</li>
 *   <li>Загрузка и управление словарями</li>
 *   <li>Умный анализ HTTP ответов</li>
 *   <li>Поддержка нескольких стратегий обхода</li>
 *   <li>Fast-cancel при обнаружении критичных находок</li>
 *   <li>Адаптивная задержка при rate limiting</li>
 * </ul>
 *
 * <p>Пример использования:
 * <pre>
 * DiscoveryConfig config = DiscoveryConfig.builder()
 *     .strategy(DiscoveryConfig.DiscoveryStrategy.HYBRID)
 *     .maxDepth(4)
 *     .fastCancel(true)
 *     .build();
 *
 * EndpointDiscoveryEngine engine = new EndpointDiscoveryEngine(
 *     httpClient, config);
 *
 * DiscoveryReport report = engine.discover(
 *     operations, "https://api.example.com");
 * </pre>
 */
public final class EndpointDiscoveryEngine {
    private static final Logger logger = Logger.getLogger(EndpointDiscoveryEngine.class.getName());

    private final HttpClient httpClient;
    private final DiscoveryConfig config;
    private final WordlistManager wordlistManager;
    private final ResponseAnalyzer responseAnalyzer;
    private final Map<DiscoveryConfig.DiscoveryStrategy, DiscoveryStrategy> strategies;
    private final AnalysisProgressListener progressListener;

    public EndpointDiscoveryEngine(HttpClient httpClient, DiscoveryConfig config) {
        this(httpClient, config, AnalysisProgressListener.noOp());
    }

    public EndpointDiscoveryEngine(HttpClient httpClient, DiscoveryConfig config,
                                   AnalysisProgressListener progressListener) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient cannot be null");
        this.config = Objects.requireNonNull(config, "config cannot be null");
        this.progressListener = Objects.requireNonNull(progressListener, "progressListener cannot be null");

        this.wordlistManager = new WordlistManager(config.getWordlistDirectory());
        this.responseAnalyzer = new ResponseAnalyzer();

        // Initialize available strategies
        this.strategies = new EnumMap<>(DiscoveryConfig.DiscoveryStrategy.class);
        this.strategies.put(DiscoveryConfig.DiscoveryStrategy.TOP_DOWN, new TopDownDiscoveryStrategy());
        this.strategies.put(DiscoveryConfig.DiscoveryStrategy.BOTTOM_UP, new BottomUpDiscoveryStrategy());
        this.strategies.put(DiscoveryConfig.DiscoveryStrategy.HYBRID, new HybridDiscoveryStrategy());

        initialize();
    }

    /**
     * Инициализирует движок: загружает словари, устанавливает baseline.
     */
    private void initialize() {
        logger.info("Initializing Endpoint Discovery Engine");
        logger.info("Configuration: " + config);

        // Load wordlists
        int loaded = wordlistManager.loadAllWordlists();
        logger.info("Loaded " + loaded + " wordlist(s) from: " + config.getWordlistDirectory());

        if (loaded == 0) {
            logger.warning("No wordlists loaded! Discovery may not find anything.");
        }
    }

    /**
     * Выполняет обнаружение незадокументированных эндпоинтов.
     *
     * @param operations документированные операции из спецификации
     * @param baseUrl базовый URL API для тестирования
     * @return отчет об обнаружении
     */
    public DiscoveryReport discover(List<OperationSpec> operations, String baseUrl) {
        Instant startTime = Instant.now();
        logger.info("Starting endpoint discovery for: " + baseUrl);
        logger.info("Documented endpoints: " + operations.size());

        // Estimate total steps based on config
        int estimatedSteps = estimateSteps();

        // Set discovery phase with estimated steps
        progressListener.onPhaseChange("endpoint-discovery", estimatedSteps);
        progressListener.onLog("INFO", "🗺️ Initializing Endpoint Discovery (Strategy: " + config.getStrategy() + ")");
        progressListener.onLog("INFO", "Configuration: Max depth=" + config.getMaxDepth() +
            ", Max requests=" + config.getMaxTotalRequests() + ", Fast cancel=" + config.isFastCancel());

        int currentStep = 0;
        progressListener.onStepComplete(++currentStep, "Building path tree from " + operations.size() + " documented endpoints");

        // Build path tree from specification
        PathTreeBuilder treeBuilder = new PathTreeBuilder();
        PathNode root = treeBuilder.buildTree(operations);

        if (config.isVerbose()) {
            logger.info("Path tree structure:\n" + treeBuilder.printTree());
            progressListener.onLog("INFO", "Path tree built with " + countNodes(root) + " nodes");
        }

        progressListener.onStepComplete(++currentStep, "Establishing baseline 404 response pattern");
        // Establish baseline 404 response
        responseAnalyzer.establishBaseline(baseUrl, httpClient);
        progressListener.onLog("INFO", "Baseline established for accurate endpoint detection");

        progressListener.onStepComplete(++currentStep, "Loading wordlists for discovery");
        int wordlistCount = wordlistManager.getAllWordlists().size();
        int totalWords = wordlistManager.getAllWordlists().stream()
            .mapToInt(w -> w.getWords().size())
            .sum();
        progressListener.onLog("INFO", "Loaded " + wordlistCount + " wordlist(s) with " + totalWords + " total words");

        progressListener.onStepComplete(++currentStep, "Starting " + config.getStrategy() + " discovery strategy");
        progressListener.onLog("INFO", "🔍 Exploring API structure using " + config.getStrategy() + " strategy...");

        // Create atomic counter for HTTP requests (shared with strategy for progress tracking)
        java.util.concurrent.atomic.AtomicInteger httpRequestCounter = new java.util.concurrent.atomic.AtomicInteger(currentStep);

        // Execute discovery based on strategy - it will update httpRequestCounter
        List<DiscoveryResult> results = executeDiscovery(root, baseUrl, httpRequestCounter, estimatedSteps);

        // Final step - ensure we reach 100%
        progressListener.onStepComplete(estimatedSteps, "Deduplicating and finalizing results");

        Instant endTime = Instant.now();
        Duration duration = Duration.between(startTime, endTime);

        logger.info("Discovery completed in " + duration.toSeconds() + "s");
        logger.info("Found " + results.size() + " undocumented endpoint(s)");
        progressListener.onLog("INFO", "✓ Discovery completed: found " + results.size() + " undocumented endpoint(s) in " + duration.toSeconds() + "s");

        return new DiscoveryReport(results, startTime, endTime, config);
    }

    /**
     * Оценивает количество шагов для прогресс-бара.
     * Считаем на основе HTTP запросов для точного прогресса и ETA.
     */
    private int estimateSteps() {
        // Get total words from all wordlists
        int totalWords = wordlistManager.getAllWordlists().stream()
            .mapToInt(w -> w.getWords().size())
            .sum();

        if (totalWords == 0) {
            totalWords = 100; // Default if no wordlists loaded
        }

        // Estimate HTTP requests: words × depth × methods
        // Each word will be tested at each depth with each method
        int httpMethods = 5; // GET, POST, PUT, DELETE, PATCH
        int estimatedHttpRequests = totalWords * config.getMaxDepth() * httpMethods;

        // Cap at maxTotalRequests if it's set and reasonable
        if (config.getMaxTotalRequests() > 0 && config.getMaxTotalRequests() < estimatedHttpRequests) {
            estimatedHttpRequests = config.getMaxTotalRequests();
        }

        // Add setup steps (tree building, baseline, wordlist loading)
        int setupSteps = 3;

        logger.info("Estimated " + estimatedHttpRequests + " HTTP requests for discovery progress tracking");
        return setupSteps + estimatedHttpRequests;
    }

    /**
     * Подсчитывает количество узлов в дереве.
     */
    private int countNodes(PathNode node) {
        int count = 1; // Current node
        for (PathNode child : node.getChildren().values()) {
            count += countNodes(child);
        }
        return count;
    }

    /**
     * Выполняет discovery согласно выбранной стратегии.
     */
    private List<DiscoveryResult> executeDiscovery(PathNode root, String baseUrl,
                                                     java.util.concurrent.atomic.AtomicInteger httpRequestCounter,
                                                     int totalSteps) {
        DiscoveryStrategy strategy = strategies.get(config.getStrategy());

        if (strategy == null) {
            logger.warning("Unknown strategy: " + config.getStrategy() + ", using TOP_DOWN");
            strategy = strategies.get(DiscoveryConfig.DiscoveryStrategy.TOP_DOWN);
        }

        logger.info("Using " + strategy.getName() + " discovery strategy");

        // Wrap progress listener to update progress after each HTTP request
        AnalysisProgressListener wrappedListener = new AnalysisProgressListener() {
            @Override
            public void onPhaseChange(String phase, int totalSteps) {
                // Don't change phase - we're already in endpoint-discovery phase
            }

            @Override
            public void onStepComplete(int currentStep, String message) {
                // Ignore step updates from strategy - we track HTTP requests instead
            }

            @Override
            public void onLog(String level, String message) {
                progressListener.onLog(level, message);
            }

            // Add method for updating progress on HTTP request
            public void onHttpRequest() {
                int step = httpRequestCounter.incrementAndGet();
                progressListener.onStepComplete(step, null);
            }
        };

        // Pass wrapped listener to strategy
        List<DiscoveryResult> results = strategy.discover(
            root, baseUrl, httpClient, wordlistManager, responseAnalyzer, config, wrappedListener);

        // Deduplicate results
        return deduplicateResults(results);
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

        logger.info("Deduplicated " + results.size() + " results to " + uniqueResults.size());
        return new ArrayList<>(uniqueResults.values());
    }

    /**
     * Получает менеджер словарей для внешнего использования.
     */
    public WordlistManager getWordlistManager() {
        return wordlistManager;
    }

    /**
     * Получает конфигурацию.
     */
    public DiscoveryConfig getConfig() {
        return config;
    }

    /**
     * Отчет об обнаружении незадокументированных эндпоинтов.
     */
    public static final class DiscoveryReport {
        private final List<DiscoveryResult> results;
        private final Instant startTime;
        private final Instant endTime;
        private final DiscoveryConfig config;

        public DiscoveryReport(List<DiscoveryResult> results, Instant startTime,
                               Instant endTime, DiscoveryConfig config) {
            this.results = Collections.unmodifiableList(new ArrayList<>(results));
            this.startTime = startTime;
            this.endTime = endTime;
            this.config = config;
        }

        public List<DiscoveryResult> getResults() {
            return results;
        }

        public int getTotalCount() {
            return results.size();
        }

        public List<DiscoveryResult> getCriticalResults() {
            return results.stream()
                .filter(r -> r.getSeverity() == model.Severity.CRITICAL)
                .collect(Collectors.toList());
        }

        public List<DiscoveryResult> getHighResults() {
            return results.stream()
                .filter(r -> r.getSeverity() == model.Severity.HIGH)
                .collect(Collectors.toList());
        }

        public Map<model.Severity, Long> getCountBySeverity() {
            return results.stream()
                .collect(Collectors.groupingBy(
                    DiscoveryResult::getSeverity,
                    Collectors.counting()
                ));
        }

        public Map<DiscoveryResult.DiscoveryMethod, Long> getCountByMethod() {
            return results.stream()
                .collect(Collectors.groupingBy(
                    DiscoveryResult::getDiscoveryMethod,
                    Collectors.counting()
                ));
        }

        public Duration getDuration() {
            return Duration.between(startTime, endTime);
        }

        public Instant getStartTime() {
            return startTime;
        }

        public Instant getEndTime() {
            return endTime;
        }

        public DiscoveryConfig getConfig() {
            return config;
        }

        public boolean hasFindings() {
            return !results.isEmpty();
        }

        public boolean hasCriticalFindings() {
            return results.stream().anyMatch(r -> r.getSeverity() == model.Severity.CRITICAL);
        }

        @Override
        public String toString() {
            return "DiscoveryReport{" +
                   "total=" + getTotalCount() +
                   ", critical=" + getCriticalResults().size() +
                   ", high=" + getHighResults().size() +
                   ", duration=" + getDuration().toSeconds() + "s" +
                   '}';
        }
    }
}
