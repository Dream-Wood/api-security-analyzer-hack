package active.scanner;

import java.util.*;

/**
 * Context for a vulnerability scan, providing configuration and shared state.
 */
public final class ScanContext {
    private final String baseUrl;
    private final Map<String, String> authHeaders;
    private final Map<String, Object> sharedData;
    private final boolean verbose;
    private final int maxRequests;

    private ScanContext(Builder builder) {
        this.baseUrl = Objects.requireNonNull(builder.baseUrl, "baseUrl cannot be null");
        this.authHeaders = builder.authHeaders != null
            ? Collections.unmodifiableMap(new LinkedHashMap<>(builder.authHeaders))
            : Collections.emptyMap();
        this.sharedData = builder.sharedData != null
            ? new HashMap<>(builder.sharedData)
            : new HashMap<>();
        this.verbose = builder.verbose;
        this.maxRequests = builder.maxRequests > 0 ? builder.maxRequests : 100;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public Map<String, String> getAuthHeaders() {
        return authHeaders;
    }

    public Map<String, Object> getSharedData() {
        return sharedData;
    }

    public boolean isVerbose() {
        return verbose;
    }

    public int getMaxRequests() {
        return maxRequests;
    }

    public Optional<Object> getSharedData(String key) {
        return Optional.ofNullable(sharedData.get(key));
    }

    public void putSharedData(String key, Object value) {
        sharedData.put(key, value);
    }

    public String buildUrl(String path) {
        String url = baseUrl;
        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        return url + path;
    }

    public static class Builder {
        private String baseUrl;
        private Map<String, String> authHeaders;
        private Map<String, Object> sharedData;
        private boolean verbose;
        private int maxRequests;

        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        public Builder authHeaders(Map<String, String> authHeaders) {
            this.authHeaders = authHeaders;
            return this;
        }

        public Builder addAuthHeader(String key, String value) {
            if (this.authHeaders == null) {
                this.authHeaders = new LinkedHashMap<>();
            }
            this.authHeaders.put(key, value);
            return this;
        }

        public Builder sharedData(Map<String, Object> sharedData) {
            this.sharedData = sharedData;
            return this;
        }

        public Builder verbose(boolean verbose) {
            this.verbose = verbose;
            return this;
        }

        public Builder maxRequests(int maxRequests) {
            this.maxRequests = maxRequests;
            return this;
        }

        public ScanContext build() {
            return new ScanContext(this);
        }
    }
}
