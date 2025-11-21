package active.discovery.strategy;

import active.discovery.ResponseAnalyzer;
import active.discovery.WordlistManager;
import active.discovery.model.*;
import active.http.HttpClient;
import active.model.AnalysisProgressListener;
import active.model.ApiEndpoint;
import active.model.TestRequest;
import active.model.TestResponse;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

/**
 * Стратегия поиска от листьев к корню (Bottom-Up).
 * Начинает с документированных эндпоинтов (листьев) и пробует варианты
 * на более глубоких уровнях, комбинируя с известными путями.
 *
 * <p>Алгоритм:
 * <ol>
 *   <li>Найти все документированные листовые эндпоинты</li>
 *   <li>Для каждого листа:
 *     <ul>
 *       <li>Попробовать добавить дополнительные сегменты в конец</li>
 *       <li>Попробовать варианты на уровень выше (sibling paths)</li>
 *     </ul>
 *   </li>
 *   <li>Эффективен для поиска "скрытых" действий над ресурсами</li>
 * </ol>
 *
 * <p>Пример:
 * <pre>
 * Документировано: GET /api/v1/users/{id}
 * Попробует:
 *   - /api/v1/users/{id}/activate
 *   - /api/v1/users/{id}/deactivate
 *   - /api/v1/users/{id}/permissions
 * </pre>
 */
public class BottomUpDiscoveryStrategy implements DiscoveryStrategy {
    private static final Logger logger = Logger.getLogger(BottomUpDiscoveryStrategy.class.getName());

    private static final List<String> HTTP_METHODS = List.of("GET", "POST", "PUT", "DELETE", "PATCH");
    private static final String PLACEHOLDER_ID = "1"; // Для path parameters

    @Override
    public String getName() {
        return "Bottom-Up";
    }

    @Override
    public String getDescription() {
        return "Searches from documented endpoints (leaves) adding segments and exploring deeper levels";
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

        logger.info("Starting Bottom-Up discovery");
        progressListener.onLog("INFO", "Discovery: Starting Bottom-Up strategy from documented endpoints");

        List<DiscoveryResult> results = new ArrayList<>();
        AtomicInteger requestCount = new AtomicInteger(0);

        // Find all leaf nodes (documented endpoints)
        List<PathNodeWithPath> leaves = collectLeaves(root, "");

        logger.info("Found " + leaves.size() + " documented endpoints to explore from");
        progressListener.onLog("INFO", "Discovery: Found " + leaves.size() + " documented endpoints as starting points");

        // Explore from each leaf
        for (PathNodeWithPath leaf : leaves) {
            // Check request limit (only if > 0, 0 means unlimited)
            if (config.getMaxTotalRequests() > 0 && requestCount.get() >= config.getMaxTotalRequests()) {
                logger.warning("Reached max total requests limit");
                progressListener.onLog("WARNING", "Discovery: Max requests limit reached (" + config.getMaxTotalRequests() + ")");
                break;
            }

            exploreFromLeaf(
                leaf,
                baseUrl,
                httpClient,
                wordlistManager,
                responseAnalyzer,
                config,
                results,
                requestCount,
                progressListener
            );
        }

        // Send final progress update to ensure UI shows 100%
        int finalRequests = requestCount.get();
        progressListener.onStepComplete(3 + finalRequests, null);

        logger.info("Bottom-Up discovery completed. Found " + results.size() +
                   " undocumented endpoints, made " + finalRequests + " requests");
        progressListener.onLog("INFO", "Discovery: Bottom-Up completed - " + results.size() +
            " undocumented endpoints found (" + finalRequests + " requests)");

        return results;
    }

    /**
     * Собирает все листовые узлы с их полными путями.
     */
    private List<PathNodeWithPath> collectLeaves(PathNode node, String currentPath) {
        List<PathNodeWithPath> leaves = new ArrayList<>();

        String nodePath = currentPath.isEmpty()
            ? ("/" + node.getSegment())
            : (currentPath + "/" + node.getSegment());

        if (node.getSegment().isEmpty()) {
            nodePath = "";
        }

        // Skip wildcard parameters - they accept any path, so we can't meaningfully explore deeper
        if (Boolean.TRUE.equals(node.getMetadata("wildcardParameter"))) {
            logger.fine("Skipping wildcard parameter in collectLeaves: " + nodePath);
            return leaves; // Don't add this node or explore its children
        }

        // If node has HTTP methods, it's an endpoint
        if (!node.getHttpMethods().isEmpty()) {
            leaves.add(new PathNodeWithPath(node, nodePath));
        }

        // Recursively collect from children
        for (PathNode child : node.getChildren().values()) {
            leaves.addAll(collectLeaves(child, nodePath));
        }

        return leaves;
    }

    /**
     * Исследует от документированного листа вглубь.
     */
    private void exploreFromLeaf(
            PathNodeWithPath leaf,
            String baseUrl,
            HttpClient httpClient,
            WordlistManager wordlistManager,
            ResponseAnalyzer responseAnalyzer,
            DiscoveryConfig config,
            List<DiscoveryResult> results,
            AtomicInteger requestCount,
            AnalysisProgressListener progressListener) {

        String basePath = leaf.path;
        int currentDepth = leaf.node.getDepth();

        // Skip if this leaf itself contains path parameters (including wildcards)
        // Exploring from /api/v1/backup/:filepath would just match the wildcard
        if (containsPathParameter(basePath)) {
            logger.fine("Skipping exploration from leaf with path parameter: " + basePath);
            return;
        }

        logger.fine("Exploring from leaf: " + basePath + " (depth: " + currentDepth + ")");
        progressListener.onLog("INFO", "Discovery: Exploring deeper from: " + basePath);

        // Try adding one more level (actions on resources)
        exploreNextLevel(
            basePath,
            currentDepth,
            baseUrl,
            httpClient,
            wordlistManager,
            responseAnalyzer,
            config,
            results,
            requestCount,
            progressListener
        );
    }

    /**
     * Исследует следующий уровень от базового пути.
     */
    private void exploreNextLevel(
            String basePath,
            int currentDepth,
            String baseUrl,
            HttpClient httpClient,
            WordlistManager wordlistManager,
            ResponseAnalyzer responseAnalyzer,
            DiscoveryConfig config,
            List<DiscoveryResult> results,
            AtomicInteger requestCount,
            AnalysisProgressListener progressListener) {

        // Check depth limit
        int nextDepth = currentDepth + 1;
        if (nextDepth > config.getMaxDepth()) {
            return;
        }

        // Get wordlists for next level
        List<Wordlist> wordlists = wordlistManager.getWordlistsForPosition(nextDepth);
        if (wordlists.isEmpty()) {
            return;
        }

        // Collect words to try
        Set<String> wordsToTry = new HashSet<>();
        for (Wordlist wordlist : wordlists) {
            wordsToTry.addAll(wordlist.getWords());
        }

        // Replace path parameters with placeholder
        String testBasePath = replacePathParameters(basePath);

        logger.fine("Testing " + wordsToTry.size() + " segments after " + testBasePath);

        int levelRequestCount = 0;

        for (String segment : wordsToTry) {
            // Check level request limit (0 = unlimited)
            if (config.getMaxRequestsPerLevel() > 0 && levelRequestCount >= config.getMaxRequestsPerLevel()) {
                break;
            }

            if (config.getMaxTotalRequests() > 0 && requestCount.get() >= config.getMaxTotalRequests()) {
                break;
            }

            String newPath = testBasePath + "/" + segment;

            // Try different HTTP methods
            for (String method : HTTP_METHODS) {
                if (config.getMaxTotalRequests() > 0 && requestCount.get() >= config.getMaxTotalRequests()) {
                    break;
                }

                TestResponse response = null;
                long responseTime = 0;

                try {
                    long startTime = System.currentTimeMillis();
                    response = makeRequest(baseUrl + newPath, method, httpClient);
                    responseTime = System.currentTimeMillis() - startTime;

                    // Analyze response only if request succeeded
                    if (response == null) {
                        continue; // Skip to next method
                    }

                    ResponseAnalyzer.AnalysisResult analysis =
                        responseAnalyzer.analyze(response, responseTime);

                    if (analysis.endpointExists() || analysis.endpointPossiblyExists()) {
                        // Found undocumented endpoint!
                        DiscoveryResult result = DiscoveryResult.builder()
                            .endpoint(createEndpoint(newPath, method))
                            .statusCode(analysis.statusCode())
                            .responseBody(response.getBody())
                            .responseHeaders(convertHeaders(response.getHeaders()))
                            .responseTimeMs(responseTime)
                            .discoveryMethod(DiscoveryResult.DiscoveryMethod.BOTTOM_UP)
                            .reason(analysis.reason())
                            .addMetadata("depth", nextDepth)
                            .addMetadata("confidence", analysis.confidence())
                            .addMetadata("baseEndpoint", basePath)
                            .build();

                        results.add(result);

                        logger.info("Found undocumented endpoint: " + method + " " + newPath +
                                   " (status: " + analysis.statusCode() +
                                   ", confidence: " + String.format("%.2f", analysis.confidence()) + ")");

                        // Fast cancel if configured
                        if (config.isFastCancel() && result.isDangerous()) {
                            logger.warning("Fast cancel triggered - found dangerous undocumented endpoint!");
                            return;
                        }

                        // Don't explore deeper if base path contains wildcard/path parameters
                        // Paths like /api/v1/backup/:filepath/* are all matched by the wildcard
                        // so any "found" endpoints are false positives
                        if (containsPathParameter(basePath)) {
                            logger.fine("Skipping recursive exploration from " + newPath +
                                " (base path contains wildcard/path parameter: " + basePath + ")");
                            continue; // Don't explore deeper from wildcard paths
                        }

                        // Recursively explore deeper
                        exploreNextLevel(
                            newPath,
                            nextDepth,
                            baseUrl,
                            httpClient,
                            wordlistManager,
                            responseAnalyzer,
                            config,
                            results,
                            requestCount,
                            progressListener
                        );
                    }

                    // Adaptive delay
                    if (config.isAdaptiveDelay() && response.getStatusCode() == 429) {
                        logger.warning("Rate limited (429), increasing delay");
                        Thread.sleep(config.getRequestDelayMs() * 2L);
                    } else if (config.getRequestDelayMs() > 0) {
                        Thread.sleep(config.getRequestDelayMs());
                    }

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    logger.warning("Discovery interrupted");
                    return;
                } catch (Exception e) {
                    logger.fine("Error testing " + method + " " + newPath + ": " + e.getMessage());
                } finally {
                    // Update progress counter even if request failed
                    // This ensures progress bar moves forward even with errors
                    int totalRequests = requestCount.incrementAndGet();
                    levelRequestCount++;

                    // Throttle progress updates: only report every 50 requests or every 1%
                    // This reduces WebSocket spam from 9000+ messages to ~100 messages
                    if (totalRequests % 50 == 0 || totalRequests % Math.max(1, config.getMaxTotalRequests() / 100) == 0) {
                        progressListener.onStepComplete(3 + totalRequests, null);
                    }
                }
            }
        }
    }

    /**
     * Проверяет, содержит ли путь WILDCARD параметры (не обычные параметры).
     * Wildcard параметры принимают произвольные пути и создают false positives.
     *
     * Обычные параметры (:user_id, :doc_id) - OK, можно исследовать
     * Wildcard параметры (:filepath, :path) - НЕ исследовать!
     */
    private boolean containsPathParameter(String path) {
        if (path == null || !path.contains("/:")) {
            return false;
        }

        // Check ONLY for wildcard parameter names, not all parameters!
        // These are catch-all parameters that match arbitrary paths
        return path.contains("/:filepath") ||
               path.contains("/:filename") ||
               path.contains("/:path/") ||      // /api/v1/backup/:path/something
               path.endsWith("/:path") ||       // /api/v1/backup/:path
               path.contains("/:pathparam") ||
               path.contains("/:catchall") ||
               path.contains("/:any") ||
               path.contains("/:path:");  // Flask <path:*> becomes :path:*
    }

    /**
     * Заменяет path параметры ({id}, {userId}) на placeholder значение.
     */
    private String replacePathParameters(String path) {
        // Replace :id or {id} patterns with actual value
        return path.replaceAll(":\\w+", PLACEHOLDER_ID)
                   .replaceAll("\\{\\w+\\}", PLACEHOLDER_ID);
    }

    /**
     * Выполняет HTTP запрос.
     */
    private TestResponse makeRequest(String url, String method, HttpClient httpClient) {
        TestRequest.Builder requestBuilder = TestRequest.builder()
            .url(url)
            .method(method);

        // Add body for methods that support it
        if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
            requestBuilder.body("").bodyContentType("application/json");
        }

        return httpClient.execute(requestBuilder.build());
    }

    /**
     * Создает объект ApiEndpoint.
     */
    private ApiEndpoint createEndpoint(String path, String method) {
        return ApiEndpoint.builder()
            .path(path)
            .method(method)
            .addMetadata("documented", false)
            .build();
    }

    /**
     * Преобразует Map<String, List<String>> в Map<String, String>, беря первое значение из списка.
     */
    private Map<String, String> convertHeaders(Map<String, List<String>> headers) {
        if (headers == null || headers.isEmpty()) {
            return Map.of();
        }
        Map<String, String> result = new HashMap<>();
        headers.forEach((key, values) -> {
            if (values != null && !values.isEmpty()) {
                result.put(key, values.get(0));
            }
        });
        return result;
    }

    /**
     * Вспомогательный record для хранения узла с его полным путем.
     */
    private record PathNodeWithPath(PathNode node, String path) {}
}
