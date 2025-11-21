package active.discovery.model;

import java.time.Duration;
import java.util.*;

/**
 * Конфигурация для процесса discovery эндпоинтов.
 */
public final class DiscoveryConfig {
    private final DiscoveryStrategy strategy;
    private final boolean fastCancel;
    private final int maxDepth;
    private final int maxRequestsPerLevel;
    private final int maxTotalRequests;
    private final int requestDelayMs;
    private final boolean adaptiveDelay;
    private final boolean cacheResults;
    private final Duration cacheTtl;
    private final List<String> excludePatterns;
    private final List<Integer> interestingStatusCodes;
    private final String wordlistDirectory;
    private final List<String> enabledWordlists;
    private final int parallelism;
    private final boolean verbose;

    private DiscoveryConfig(Builder builder) {
        this.strategy = builder.strategy != null ? builder.strategy : DiscoveryStrategy.HYBRID;
        this.fastCancel = builder.fastCancel;
        this.maxDepth = builder.maxDepth > 0 ? builder.maxDepth : 8; // Increased from 5 to 8 for deep paths
        this.maxRequestsPerLevel = builder.maxRequestsPerLevel; // 0 = unlimited (no per-level limit)
        // Default maxTotalRequests = 0 (unlimited) for long analysis sessions
        // User can set a limit if needed
        this.maxTotalRequests = builder.maxTotalRequests;
        this.requestDelayMs = Math.max(0, builder.requestDelayMs);
        this.adaptiveDelay = builder.adaptiveDelay;
        this.cacheResults = builder.cacheResults;
        this.cacheTtl = builder.cacheTtl != null ? builder.cacheTtl : Duration.ofHours(24);
        this.excludePatterns = builder.excludePatterns != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.excludePatterns))
            : List.of(".*\\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf)$");
        this.interestingStatusCodes = builder.interestingStatusCodes != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.interestingStatusCodes))
            : List.of(200, 201, 204, 301, 302, 401, 403, 405, 500, 503);
        this.wordlistDirectory = builder.wordlistDirectory != null ? builder.wordlistDirectory : "./wordlists";
        this.enabledWordlists = builder.enabledWordlists != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.enabledWordlists))
            : Collections.emptyList();
        this.parallelism = builder.parallelism > 0 ? builder.parallelism : 4;
        this.verbose = builder.verbose;
    }

    public static Builder builder() {
        return new Builder();
    }

    public DiscoveryStrategy getStrategy() {
        return strategy;
    }

    public boolean isFastCancel() {
        return fastCancel;
    }

    public int getMaxDepth() {
        return maxDepth;
    }

    public int getMaxRequestsPerLevel() {
        return maxRequestsPerLevel;
    }

    public int getMaxTotalRequests() {
        return maxTotalRequests;
    }

    public int getRequestDelayMs() {
        return requestDelayMs;
    }

    public boolean isAdaptiveDelay() {
        return adaptiveDelay;
    }

    public boolean isCacheResults() {
        return cacheResults;
    }

    public Duration getCacheTtl() {
        return cacheTtl;
    }

    public List<String> getExcludePatterns() {
        return excludePatterns;
    }

    public List<Integer> getInterestingStatusCodes() {
        return interestingStatusCodes;
    }

    public String getWordlistDirectory() {
        return wordlistDirectory;
    }

    public List<String> getEnabledWordlists() {
        return enabledWordlists;
    }

    public int getParallelism() {
        return parallelism;
    }

    public boolean isVerbose() {
        return verbose;
    }

    @Override
    public String toString() {
        return "DiscoveryConfig{" +
               "strategy=" + strategy +
               ", fastCancel=" + fastCancel +
               ", maxDepth=" + maxDepth +
               ", maxRequests=" + maxTotalRequests +
               ", wordlistDir='" + wordlistDirectory + '\'' +
               '}';
    }

    /**
     * Стратегия обхода дерева путей.
     */
    public enum DiscoveryStrategy {
        /** От корня к листьям */
        TOP_DOWN,

        /** От листьев к корню */
        BOTTOM_UP,

        /** Комбинированный подход */
        HYBRID
    }

    public static class Builder {
        private DiscoveryStrategy strategy;
        private boolean fastCancel = false;
        private int maxDepth = 8; // Increased from 5 to 8 for deep paths
        private int maxRequestsPerLevel = 0; // 0 = unlimited (no per-level limit)
        private int maxTotalRequests = 0; // 0 = unlimited (better for long analysis)
        private int requestDelayMs = 250; // Increased from 100ms to prevent port exhaustion
        private boolean adaptiveDelay = true;
        private boolean cacheResults = true;
        private Duration cacheTtl;
        private List<String> excludePatterns;
        private List<Integer> interestingStatusCodes;
        private String wordlistDirectory;
        private List<String> enabledWordlists;
        private int parallelism = 4;
        private boolean verbose = false;

        public Builder strategy(DiscoveryStrategy strategy) {
            this.strategy = strategy;
            return this;
        }

        public Builder fastCancel(boolean fastCancel) {
            this.fastCancel = fastCancel;
            return this;
        }

        public Builder maxDepth(int maxDepth) {
            this.maxDepth = maxDepth;
            return this;
        }

        public Builder maxRequestsPerLevel(int maxRequestsPerLevel) {
            this.maxRequestsPerLevel = maxRequestsPerLevel;
            return this;
        }

        public Builder maxTotalRequests(int maxTotalRequests) {
            this.maxTotalRequests = maxTotalRequests;
            return this;
        }

        public Builder requestDelayMs(int requestDelayMs) {
            this.requestDelayMs = requestDelayMs;
            return this;
        }

        public Builder adaptiveDelay(boolean adaptiveDelay) {
            this.adaptiveDelay = adaptiveDelay;
            return this;
        }

        public Builder cacheResults(boolean cacheResults) {
            this.cacheResults = cacheResults;
            return this;
        }

        public Builder cacheTtl(Duration cacheTtl) {
            this.cacheTtl = cacheTtl;
            return this;
        }

        public Builder excludePatterns(List<String> excludePatterns) {
            this.excludePatterns = new ArrayList<>(excludePatterns);
            return this;
        }

        public Builder addExcludePattern(String pattern) {
            if (this.excludePatterns == null) {
                this.excludePatterns = new ArrayList<>();
            }
            this.excludePatterns.add(pattern);
            return this;
        }

        public Builder interestingStatusCodes(List<Integer> interestingStatusCodes) {
            this.interestingStatusCodes = new ArrayList<>(interestingStatusCodes);
            return this;
        }

        public Builder addInterestingStatusCode(int statusCode) {
            if (this.interestingStatusCodes == null) {
                this.interestingStatusCodes = new ArrayList<>();
            }
            this.interestingStatusCodes.add(statusCode);
            return this;
        }

        public Builder wordlistDirectory(String wordlistDirectory) {
            this.wordlistDirectory = wordlistDirectory;
            return this;
        }

        public Builder enabledWordlists(List<String> enabledWordlists) {
            this.enabledWordlists = new ArrayList<>(enabledWordlists);
            return this;
        }

        public Builder addEnabledWordlist(String wordlist) {
            if (this.enabledWordlists == null) {
                this.enabledWordlists = new ArrayList<>();
            }
            this.enabledWordlists.add(wordlist);
            return this;
        }

        public Builder parallelism(int parallelism) {
            this.parallelism = parallelism;
            return this;
        }

        public Builder verbose(boolean verbose) {
            this.verbose = verbose;
            return this;
        }

        public DiscoveryConfig build() {
            return new DiscoveryConfig(this);
        }
    }
}
