package active.model;

import java.util.*;

/**
 * Represents an HTTP request to be executed during active testing.
 */
public final class TestRequest {
    private final String url;
    private final String method;
    private final Map<String, String> headers;
    private final Map<String, String> queryParams;
    private final String body;
    private final String bodyContentType;
    private final int timeoutMs;

    private TestRequest(Builder builder) {
        this.url = Objects.requireNonNull(builder.url, "url cannot be null");
        this.method = Objects.requireNonNull(builder.method, "method cannot be null").toUpperCase();
        this.headers = builder.headers != null
            ? Collections.unmodifiableMap(new LinkedHashMap<>(builder.headers))
            : Collections.emptyMap();
        this.queryParams = builder.queryParams != null
            ? Collections.unmodifiableMap(new LinkedHashMap<>(builder.queryParams))
            : Collections.emptyMap();
        this.body = builder.body;
        this.bodyContentType = builder.bodyContentType;
        this.timeoutMs = builder.timeoutMs > 0 ? builder.timeoutMs : 30000; // Default 30s
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getUrl() {
        return url;
    }

    public String getMethod() {
        return method;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public Map<String, String> getQueryParams() {
        return queryParams;
    }

    public String getBody() {
        return body;
    }

    public String getBodyContentType() {
        return bodyContentType;
    }

    public int getTimeoutMs() {
        return timeoutMs;
    }

    public String getFullUrl() {
        if (queryParams.isEmpty()) {
            return url;
        }

        StringBuilder fullUrl = new StringBuilder(url);
        fullUrl.append(url.contains("?") ? "&" : "?");

        queryParams.forEach((key, value) -> {
            fullUrl.append(key).append("=").append(value).append("&");
        });

        // Remove trailing '&'
        if (fullUrl.charAt(fullUrl.length() - 1) == '&') {
            fullUrl.setLength(fullUrl.length() - 1);
        }

        return fullUrl.toString();
    }

    @Override
    public String toString() {
        return method + " " + getFullUrl();
    }

    public static class Builder {
        private String url;
        private String method;
        private Map<String, String> headers;
        private Map<String, String> queryParams;
        private String body;
        private String bodyContentType;
        private int timeoutMs;

        public Builder url(String url) {
            this.url = url;
            return this;
        }

        public Builder method(String method) {
            this.method = method;
            return this;
        }

        public Builder headers(Map<String, String> headers) {
            this.headers = headers;
            return this;
        }

        public Builder addHeader(String key, String value) {
            if (this.headers == null) {
                this.headers = new LinkedHashMap<>();
            }
            this.headers.put(key, value);
            return this;
        }

        public Builder queryParams(Map<String, String> queryParams) {
            this.queryParams = queryParams;
            return this;
        }

        public Builder addQueryParam(String key, String value) {
            if (this.queryParams == null) {
                this.queryParams = new LinkedHashMap<>();
            }
            this.queryParams.put(key, value);
            return this;
        }

        public Builder body(String body) {
            this.body = body;
            return this;
        }

        public Builder bodyContentType(String bodyContentType) {
            this.bodyContentType = bodyContentType;
            return this;
        }

        public Builder timeoutMs(int timeoutMs) {
            this.timeoutMs = timeoutMs;
            return this;
        }

        public TestRequest build() {
            return new TestRequest(this);
        }
    }
}
