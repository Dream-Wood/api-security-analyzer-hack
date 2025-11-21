package active.discovery;

import active.discovery.model.PathNode;
import model.OperationSpec;

import java.util.*;
import java.util.logging.Logger;

/**
 * Строит дерево путей (Trie) из OpenAPI спецификации.
 * Дерево используется для эффективного поиска незадокументированных эндпоинтов.
 *
 * <p>Пример:
 * <pre>
 * Спецификация:
 *   GET  /api/v1/users
 *   POST /api/v1/users
 *   GET  /api/v2/products
 *
 * Дерево:
 *   /
 *   └── api (documented)
 *       ├── v1 (documented)
 *       │   └── users (documented, GET/POST)
 *       └── v2 (documented)
 *           └── products (documented, GET)
 * </pre>
 */
public final class PathTreeBuilder {
    private static final Logger logger = Logger.getLogger(PathTreeBuilder.class.getName());

    private final PathNode root;

    public PathTreeBuilder() {
        this.root = PathNode.builder()
            .segment("")
            .depth(0)
            .documented(true)
            .build();
    }

    /**
     * Строит дерево из списка операций спецификации.
     *
     * @param operations список операций из OpenAPI спецификации
     * @return корневой узел дерева
     */
    public PathNode buildTree(List<OperationSpec> operations) {
        logger.info("Building path tree from " + operations.size() + " operations");

        for (OperationSpec operation : operations) {
            addPath(operation.getPath(), operation.getMethod(), operation);
        }

        logTreeStatistics();
        return root;
    }

    /**
     * Добавляет путь в дерево.
     *
     * @param path полный путь (например, "/api/v1/users")
     * @param method HTTP метод
     * @param operation спецификация операции
     */
    public void addPath(String path, String method, OperationSpec operation) {
        if (path == null || path.isEmpty()) {
            return;
        }

        // Normalize path: remove leading/trailing slashes
        path = normalizePath(path);

        String[] segments = path.split("/");
        PathNode currentNode = root;
        int depth = 1;

        for (String segment : segments) {
            if (segment.isEmpty()) {
                continue;
            }

            // Handle path parameters: {id}, {userId} -> :id, :userId
            String normalizedSegment = normalizeSegment(segment);

            PathNode childNode = currentNode.getChild(normalizedSegment).orElse(null);

            if (childNode == null) {
                // Create new node
                childNode = PathNode.builder()
                    .segment(normalizedSegment)
                    .depth(depth)
                    .documented(true)
                    .build();

                currentNode.addChild(childNode);
            }

            // Set metadata for path parameters (even if node already exists)
            // This ensures wildcard detection works for all operations on the same path
            if (isPathParameter(segment)) {
                childNode.putMetadata("pathParameter", true);
                childNode.putMetadata("originalSegment", segment);

                // Mark wildcard parameters (e.g., <path:filepath>)
                if (isWildcardParameter(segment)) {
                    childNode.putMetadata("wildcardParameter", true);
                    logger.fine("Marked wildcard parameter: " + segment + " at depth " + depth);
                }
            }

            // Add HTTP method to the final node
            if (depth == segments.length) {
                childNode.addHttpMethod(method);

                // Add operation metadata
                if (operation.getOperationId() != null) {
                    childNode.putMetadata("operationId_" + method, operation.getOperationId());
                }
                if (operation.getSummary() != null) {
                    childNode.putMetadata("summary_" + method, operation.getSummary());
                }
            }

            currentNode = childNode;
            depth++;
        }
    }

    /**
     * Нормализует путь: удаляет начальные/конечные слэши.
     */
    private String normalizePath(String path) {
        if (path.startsWith("/")) {
            path = path.substring(1);
        }
        if (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return path;
    }

    /**
     * Нормализует сегмент пути.
     * Преобразует {id} -> :id, <id> -> :id для единообразия.
     */
    private String normalizeSegment(String segment) {
        if (isPathParameter(segment)) {
            // Extract parameter name from {userId}, <userId>, <int:userId>, <path:filepath>
            String paramName = extractParameterName(segment);
            return ":" + paramName;
        }
        return segment;
    }

    /**
     * Проверяет, является ли сегмент path параметром.
     * Поддерживает форматы: {id}, <id>, <int:id>, <path:filepath>
     */
    private boolean isPathParameter(String segment) {
        return (segment.startsWith("{") && segment.endsWith("}")) ||
               (segment.startsWith("<") && segment.endsWith(">"));
    }

    /**
     * Извлекает имя параметра из сегмента.
     * {userId} -> userId
     * <userId> -> userId
     * <int:userId> -> int:userId
     * <path:filepath> -> path:filepath
     */
    private String extractParameterName(String segment) {
        if (segment.startsWith("{") && segment.endsWith("}")) {
            return segment.substring(1, segment.length() - 1);
        }
        if (segment.startsWith("<") && segment.endsWith(">")) {
            return segment.substring(1, segment.length() - 1);
        }
        return segment;
    }

    /**
     * Проверяет, является ли параметр wildcard (catch-all).
     * Примеры: <path:filepath>, <filepath>, {filepath}, {path}, {pathparam}
     *
     * Wildcard/catch-all параметры принимают произвольные пути, поэтому
     * тестирование слов из словаря на них создает только false positives.
     */
    private boolean isWildcardParameter(String segment) {
        if (!isPathParameter(segment)) {
            return false;
        }
        String paramName = extractParameterName(segment);

        // Flask/FastAPI wildcard parameters start with "path:"
        if (paramName.startsWith("path:")) {
            return true;
        }

        // Check by parameter name - common wildcard parameter names
        // These typically appear in endpoints like /backup/{filepath}, /download/{path}
        String lowerName = paramName.toLowerCase();
        return lowerName.equals("filepath") ||
               lowerName.equals("filename") ||
               lowerName.equals("path") ||
               lowerName.equals("pathparam") ||
               lowerName.equals("catchall") ||
               lowerName.equals("any") ||
               lowerName.contains("wildcard");
    }

    /**
     * Получает корневой узел дерева.
     */
    public PathNode getRoot() {
        return root;
    }

    /**
     * Находит узел по полному пути.
     *
     * @param path полный путь
     * @return узел или empty
     */
    public Optional<PathNode> findNode(String path) {
        path = normalizePath(path);
        String[] segments = path.split("/");

        PathNode currentNode = root;
        for (String segment : segments) {
            if (segment.isEmpty()) {
                continue;
            }

            String normalizedSegment = normalizeSegment(segment);
            Optional<PathNode> childNode = currentNode.getChild(normalizedSegment);

            if (childNode.isEmpty()) {
                return Optional.empty();
            }

            currentNode = childNode.get();
        }

        return Optional.of(currentNode);
    }

    /**
     * Получает все листовые узлы (эндпоинты).
     */
    public List<PathNode> getLeafNodes() {
        List<PathNode> leaves = new ArrayList<>();
        collectLeafNodes(root, leaves);
        return leaves;
    }

    /**
     * Рекурсивно собирает листовые узлы.
     */
    private void collectLeafNodes(PathNode node, List<PathNode> leaves) {
        if (node.isLeaf() && node.isEndpoint()) {
            leaves.add(node);
        }

        for (PathNode child : node.getChildren().values()) {
            collectLeafNodes(child, leaves);
        }
    }

    /**
     * Получает все узлы на определенной глубине.
     *
     * @param depth глубина (0 = root)
     * @return список узлов
     */
    public List<PathNode> getNodesAtDepth(int depth) {
        List<PathNode> nodes = new ArrayList<>();
        collectNodesAtDepth(root, depth, nodes);
        return nodes;
    }

    /**
     * Рекурсивно собирает узлы на заданной глубине.
     */
    private void collectNodesAtDepth(PathNode node, int targetDepth, List<PathNode> nodes) {
        if (node.getDepth() == targetDepth) {
            nodes.add(node);
        }

        if (node.getDepth() < targetDepth) {
            for (PathNode child : node.getChildren().values()) {
                collectNodesAtDepth(child, targetDepth, nodes);
            }
        }
    }

    /**
     * Получает максимальную глубину дерева.
     */
    public int getMaxDepth() {
        return calculateMaxDepth(root, 0);
    }

    /**
     * Рекурсивно вычисляет максимальную глубину.
     */
    private int calculateMaxDepth(PathNode node, int currentMax) {
        int max = Math.max(currentMax, node.getDepth());

        for (PathNode child : node.getChildren().values()) {
            max = Math.max(max, calculateMaxDepth(child, max));
        }

        return max;
    }

    /**
     * Строит полный путь до узла.
     *
     * @param node узел
     * @return полный путь
     */
    public String buildFullPath(PathNode node) {
        // Этот метод требует обратной связи от узла к родителю
        // Для упрощения, сохраним полные пути в метаданных при построении
        // Или используем альтернативный подход с хранением родительских ссылок
        return node.getSegment();
    }

    /**
     * Логирует статистику построенного дерева.
     */
    private void logTreeStatistics() {
        int totalNodes = countNodes(root);
        int leafNodes = getLeafNodes().size();
        int maxDepth = getMaxDepth();

        logger.info(String.format("Path tree built: %d total nodes, %d endpoints, max depth: %d",
            totalNodes, leafNodes, maxDepth));
    }

    /**
     * Подсчитывает общее количество узлов в дереве.
     */
    private int countNodes(PathNode node) {
        int count = 1; // current node

        for (PathNode child : node.getChildren().values()) {
            count += countNodes(child);
        }

        return count;
    }

    /**
     * Возвращает строковое представление дерева для отладки.
     */
    public String printTree() {
        StringBuilder sb = new StringBuilder();
        printNode(root, "", true, sb);
        return sb.toString();
    }

    /**
     * Рекурсивно печатает узел дерева.
     */
    private void printNode(PathNode node, String prefix, boolean isLast, StringBuilder sb) {
        if (!node.getSegment().isEmpty()) {
            sb.append(prefix);
            sb.append(isLast ? "└── " : "├── ");
            sb.append(node.getSegment());

            if (!node.getHttpMethods().isEmpty()) {
                sb.append(" (").append(String.join(", ", node.getHttpMethods())).append(")");
            }
            sb.append("\n");
        }

        List<PathNode> children = new ArrayList<>(node.getChildren().values());
        for (int i = 0; i < children.size(); i++) {
            String newPrefix = node.getSegment().isEmpty() ? "" : prefix + (isLast ? "    " : "│   ");
            printNode(children.get(i), newPrefix, i == children.size() - 1, sb);
        }
    }
}
