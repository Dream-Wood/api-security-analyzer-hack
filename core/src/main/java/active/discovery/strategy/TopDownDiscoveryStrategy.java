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
 * Стратегия поиска от корня к листьям (Top-Down).
 * Начинает с корня дерева и перебирает варианты на каждом уровне,
 * углубляясь только в найденные пути с возвратом назад (backtracking).
 *
 * <p>Алгоритм (DFS с backtracking):
 * <ol>
 *   <li>Начать с корня /</li>
 *   <li>Для каждого уровня глубины:
 *     <ul>
 *       <li>Взять словарь для этого уровня</li>
 *       <li>Пропустить документированные сегменты</li>
 *       <li>Проверить недокументированные варианты</li>
 *       <li>Если найден - РЕКУРСИВНО спуститься вглубь</li>
 *       <li>После исследования - ВЕРНУТЬСЯ (backtrack) и попробовать следующий вариант</li>
 *     </ul>
 *   </li>
 *   <li>Также исследовать документированные ветви дерева</li>
 * </ol>
 */
public class TopDownDiscoveryStrategy implements DiscoveryStrategy {
    private static final Logger logger = Logger.getLogger(TopDownDiscoveryStrategy.class.getName());

    private static final List<String> HTTP_METHODS = List.of("GET", "POST", "PUT", "DELETE", "PATCH");

    @Override
    public String getName() {
        return "Top-Down";
    }

    @Override
    public String getDescription() {
        return "DFS tree traversal with backtracking from root to leaves";
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

        logger.info("Starting Top-Down discovery with max depth: " + config.getMaxDepth());
        progressListener.onLog("INFO", "Discovery: Starting DFS tree traversal with backtracking");

        List<DiscoveryResult> results = new ArrayList<>();
        AtomicInteger requestCount = new AtomicInteger(0);

        // Start from root
        exploreLevel(
            root,
            "",
            0,
            baseUrl,
            httpClient,
            wordlistManager,
            responseAnalyzer,
            config,
            results,
            requestCount,
            progressListener
        );

        // Send final progress update to ensure UI shows 100%
        int finalRequests = requestCount.get();
        progressListener.onStepComplete(3 + finalRequests, null);

        logger.info("Top-Down discovery completed. Found " + results.size() +
                   " undocumented endpoints, made " + finalRequests + " requests");
        progressListener.onLog("INFO", "Discovery: Completed DFS traversal - " + results.size() +
            " undocumented endpoints found (" + finalRequests + " requests)");

        return results;
    }

    /**
     * Рекурсивно исследует уровень дерева (DFS с backtracking).
     *
     * @param currentNode текущий узел в дереве
     * @param currentPath текущий путь от корня
     * @param depth текущая глубина
     */
    private void exploreLevel(
            PathNode currentNode,
            String currentPath,
            int depth,
            String baseUrl,
            HttpClient httpClient,
            WordlistManager wordlistManager,
            ResponseAnalyzer responseAnalyzer,
            DiscoveryConfig config,
            List<DiscoveryResult> results,
            AtomicInteger requestCount,
            AnalysisProgressListener progressListener) {

        // Check depth limit
        if (depth >= config.getMaxDepth()) {
            if (config.isVerbose()) {
                progressListener.onLog("INFO", "  ".repeat(depth) + "↩ Max depth reached, backtracking from: " +
                    (currentPath.isEmpty() ? "/" : currentPath));
            }
            return;
        }

        // Check request limit (only if > 0, 0 means unlimited)
        if (config.getMaxTotalRequests() > 0 && requestCount.get() >= config.getMaxTotalRequests()) {
            logger.warning("Reached max total requests limit: " + config.getMaxTotalRequests());
            progressListener.onLog("WARNING", "Discovery: Max requests limit reached (" + config.getMaxTotalRequests() + ")");
            return;
        }

        // Skip if current node is a wildcard parameter (e.g., <path:filepath>)
        // Wildcard parameters accept ANY path, so testing wordlist against them creates false positives
        if (Boolean.TRUE.equals(currentNode.getMetadata("wildcardParameter"))) {
            String indent = "  ".repeat(depth);
            if (config.isVerbose()) {
                progressListener.onLog("INFO", indent + "⚠ Skipping wildcard parameter node: " + currentNode.getSegment() +
                    " at " + (currentPath.isEmpty() ? "/" : currentPath) + " (would match any path)");
            }
            logger.fine("Skipping wildcard parameter node at depth " + depth + ": " + currentPath);

            // Still explore documented children (but not by adding wordlist words)
            for (PathNode child : currentNode.getChildren().values()) {
                // Skip nested wildcard parameters
                if (Boolean.TRUE.equals(child.getMetadata("wildcardParameter"))) {
                    continue;
                }
                String childPath = buildPath(currentPath, child.getSegment());
                exploreLevel(child, childPath, depth + 1, baseUrl, httpClient, wordlistManager,
                    responseAnalyzer, config, results, requestCount, progressListener);
            }
            return;
        }

        // Get applicable wordlists for this depth
        List<Wordlist> wordlists = wordlistManager.getWordlistsForPosition(depth);
        if (wordlists.isEmpty()) {
            logger.fine("No wordlists for depth " + depth);
            return;
        }

        String indent = "  ".repeat(depth);
        logger.fine("Exploring depth " + depth + " at path: " + (currentPath.isEmpty() ? "/" : currentPath));
        if (config.isVerbose()) {
            progressListener.onLog("INFO", indent + "⬇ Exploring depth " + depth + ": " +
                (currentPath.isEmpty() ? "/" : currentPath) + " (" + wordlists.size() + " wordlist(s))");
        }

        // Collect all words from applicable wordlists
        Set<String> wordsToTry = new HashSet<>();
        for (Wordlist wordlist : wordlists) {
            wordsToTry.addAll(wordlist.getWords());
        }

        // Remove segments that already exist in spec (documented)
        Set<String> documentedSegments = currentNode.getChildren().keySet();
        wordsToTry.removeAll(documentedSegments);

        logger.fine("Testing " + wordsToTry.size() + " undocumented segments at depth " + depth);

        int levelRequestCount = 0;

        // Try each word
        for (String segment : wordsToTry) {
            // Check level request limit (0 = unlimited)
            if (config.getMaxRequestsPerLevel() > 0 && levelRequestCount >= config.getMaxRequestsPerLevel()) {
                logger.fine("Reached max requests per level at depth " + depth);
                break;
            }

            // Check global request limit (0 = unlimited)
            if (config.getMaxTotalRequests() > 0 && requestCount.get() >= config.getMaxTotalRequests()) {
                break;
            }

            String newPath = buildPath(currentPath, segment);

            // Try different HTTP methods
            for (String method : HTTP_METHODS) {
                if (config.getMaxTotalRequests() > 0 && requestCount.get() >= config.getMaxTotalRequests()) {
                    break;
                }

                TestResponse response = null;
                long responseTime = 0;

                try {
                    // Make request
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
                            .discoveryMethod(DiscoveryResult.DiscoveryMethod.TOP_DOWN)
                            .reason(analysis.reason())
                            .addMetadata("depth", depth)
                            .addMetadata("confidence", analysis.confidence())
                            .build();

                        results.add(result);

                        logger.info("Found undocumented endpoint: " + method + " " + newPath +
                                   " (status: " + analysis.statusCode() +
                                   ", confidence: " + String.format("%.2f", analysis.confidence()) + ")");
                        progressListener.onLog("INFO", indent + "  ✓ Found: " + method + " " + newPath +
                            " [" + analysis.statusCode() + "] (confidence: " + String.format("%.1f%%", analysis.confidence() * 100) + ")");

                        // Fast cancel if configured
                        if (config.isFastCancel() && result.isDangerous()) {
                            logger.warning("Fast cancel triggered - found dangerous undocumented endpoint!");
                            progressListener.onLog("WARNING", "⚠ Fast cancel triggered - dangerous endpoint found!");
                            return;
                        }

                        // Explore deeper from this found path (DFS - go deeper first)
                        progressListener.onLog("INFO", indent + "  → Going deeper from: " + newPath);
                        // Create temporary node for the found segment
                        PathNode newNode = PathNode.builder()
                            .segment(segment)
                            .depth(depth + 1)
                            .documented(false)
                            .addHttpMethod(method)
                            .build();

                        exploreLevel(
                            newNode,
                            newPath,
                            depth + 1,
                            baseUrl,
                            httpClient,
                            wordlistManager,
                            responseAnalyzer,
                            config,
                            results,
                            requestCount,
                            progressListener
                        );

                        // Backtracking - returned from deeper exploration
                        if (config.isVerbose()) {
                            progressListener.onLog("INFO", indent + "  ↩ Backtracked to depth " + depth + ": " +
                                (currentPath.isEmpty() ? "/" : currentPath));
                        }
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

        // Also explore documented children (follow documented branches)
        // BUT skip wildcard parameters (e.g., <path:filepath>) to avoid testing all words
        if (!currentNode.getChildren().isEmpty()) {
            int nonWildcardChildren = (int) currentNode.getChildren().values().stream()
                .filter(child -> !Boolean.TRUE.equals(child.getMetadata("wildcardParameter")))
                .count();

            if (config.isVerbose() && nonWildcardChildren > 0) {
                progressListener.onLog("INFO", indent + "→ Following " + nonWildcardChildren +
                    " documented branch(es) from: " + (currentPath.isEmpty() ? "/" : currentPath));
            }
        }

        for (PathNode child : currentNode.getChildren().values()) {
            // Skip wildcard parameters (e.g., <path:filepath>)
            // They accept ANY path, so testing wordlist against them creates false positives
            if (Boolean.TRUE.equals(child.getMetadata("wildcardParameter"))) {
                if (config.isVerbose()) {
                    progressListener.onLog("INFO", indent + "⚠ Skipping wildcard parameter: " + child.getSegment() +
                        " (would match any path)");
                }
                continue;
            }

            String childPath = buildPath(currentPath, child.getSegment());
            exploreLevel(
                child,
                childPath,
                depth + 1,
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

        // Finished exploring this level - backtrack
        if (config.isVerbose() && depth > 0) {
            progressListener.onLog("INFO", indent + "↩ Finished depth " + depth + ", returning to depth " + (depth - 1));
        }
    }

    /**
     * Строит полный путь из частей.
     */
    private String buildPath(String basePath, String segment) {
        if (basePath.isEmpty()) {
            return "/" + segment;
        }
        return basePath + "/" + segment;
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
}
