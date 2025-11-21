package active.discovery.model;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Узел в дереве путей API (Trie структура).
 * Представляет один сегмент пути (например, "api", "v2", "users").
 *
 * <p>Пример дерева:
 * <pre>
 * /
 * ├── api
 * │   ├── v1
 * │   │   ├── users (GET, POST)
 * │   │   └── posts (GET)
 * │   └── v2
 * │       └── users (GET, POST, DELETE)
 * </pre>
 */
public final class PathNode {
    private final String segment;
    private final Map<String, PathNode> children;
    private final Set<String> httpMethods;
    private final boolean documented;
    private final Map<String, Object> metadata;
    private final int depth;

    private PathNode(Builder builder) {
        this.segment = Objects.requireNonNull(builder.segment, "segment cannot be null");
        this.children = new ConcurrentHashMap<>(builder.children);
        this.httpMethods = Collections.synchronizedSet(new HashSet<>(builder.httpMethods));
        this.documented = builder.documented;
        this.metadata = new ConcurrentHashMap<>(builder.metadata);
        this.depth = builder.depth;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getSegment() {
        return segment;
    }

    public Map<String, PathNode> getChildren() {
        return Collections.unmodifiableMap(children);
    }

    public Set<String> getHttpMethods() {
        return Collections.unmodifiableSet(httpMethods);
    }

    public boolean isDocumented() {
        return documented;
    }

    public Map<String, Object> getMetadata() {
        return Collections.unmodifiableMap(metadata);
    }

    public int getDepth() {
        return depth;
    }

    /**
     * Добавляет дочерний узел.
     */
    public void addChild(PathNode child) {
        children.put(child.getSegment(), child);
    }

    /**
     * Получает дочерний узел по сегменту.
     */
    public Optional<PathNode> getChild(String segment) {
        return Optional.ofNullable(children.get(segment));
    }

    /**
     * Проверяет, есть ли дочерний узел с данным сегментом.
     */
    public boolean hasChild(String segment) {
        return children.containsKey(segment);
    }

    /**
     * Добавляет HTTP метод к узлу.
     */
    public void addHttpMethod(String method) {
        httpMethods.add(method.toUpperCase());
    }

    /**
     * Проверяет, поддерживается ли HTTP метод.
     */
    public boolean hasHttpMethod(String method) {
        return httpMethods.contains(method.toUpperCase());
    }

    /**
     * Является ли узел листом (нет дочерних узлов).
     */
    public boolean isLeaf() {
        return children.isEmpty();
    }

    /**
     * Является ли узел эндпоинтом (имеет HTTP методы).
     */
    public boolean isEndpoint() {
        return !httpMethods.isEmpty();
    }

    /**
     * Получает полный путь от корня до этого узла.
     */
    public String getFullPath() {
        // Этот метод нужно вызывать с контекстом родительского пути
        // Используется в PathTreeBuilder
        return segment;
    }

    /**
     * Добавляет метаданные.
     */
    public void putMetadata(String key, Object value) {
        metadata.put(key, value);
    }

    /**
     * Получает метаданные.
     */
    public Optional<Object> getMetadata(String key) {
        return Optional.ofNullable(metadata.get(key));
    }

    @Override
    public String toString() {
        return "PathNode{" +
               "segment='" + segment + '\'' +
               ", depth=" + depth +
               ", methods=" + httpMethods +
               ", documented=" + documented +
               ", children=" + children.size() +
               '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PathNode pathNode = (PathNode) o;
        return Objects.equals(segment, pathNode.segment) && depth == pathNode.depth;
    }

    @Override
    public int hashCode() {
        return Objects.hash(segment, depth);
    }

    public static class Builder {
        private String segment;
        private Map<String, PathNode> children = new HashMap<>();
        private Set<String> httpMethods = new HashSet<>();
        private boolean documented = false;
        private Map<String, Object> metadata = new HashMap<>();
        private int depth = 0;

        public Builder segment(String segment) {
            this.segment = segment;
            return this;
        }

        public Builder children(Map<String, PathNode> children) {
            this.children = new HashMap<>(children);
            return this;
        }

        public Builder addChild(PathNode child) {
            this.children.put(child.getSegment(), child);
            return this;
        }

        public Builder httpMethods(Set<String> httpMethods) {
            this.httpMethods = new HashSet<>(httpMethods);
            return this;
        }

        public Builder addHttpMethod(String method) {
            this.httpMethods.add(method.toUpperCase());
            return this;
        }

        public Builder documented(boolean documented) {
            this.documented = documented;
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = new HashMap<>(metadata);
            return this;
        }

        public Builder addMetadata(String key, Object value) {
            this.metadata.put(key, value);
            return this;
        }

        public Builder depth(int depth) {
            this.depth = depth;
            return this;
        }

        public PathNode build() {
            return new PathNode(this);
        }
    }
}
