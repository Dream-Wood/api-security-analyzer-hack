package active.model;

import java.util.*;

/**
 * Представляет HTTP ответ от активного тестирования.
 * Содержит код статуса, заголовки, тело ответа, время ответа и возможную ошибку.
 */
public final class TestResponse {
    private final int statusCode;
    private final Map<String, List<String>> headers;
    private final String body;
    private final long responseTimeMs;
    private final Optional<Exception> error;

    private TestResponse(Builder builder) {
        this.statusCode = builder.statusCode;
        this.headers = builder.headers != null
            ? Collections.unmodifiableMap(new LinkedHashMap<>(builder.headers))
            : Collections.emptyMap();
        this.body = builder.body;
        this.responseTimeMs = builder.responseTimeMs;
        this.error = Optional.ofNullable(builder.error);
    }

    public static Builder builder() {
        return new Builder();
    }

    public int getStatusCode() {
        return statusCode;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public String getBody() {
        return body;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    public Optional<Exception> getError() {
        return error;
    }

    public boolean isSuccessful() {
        return statusCode >= 200 && statusCode < 300;
    }

    public boolean isClientError() {
        return statusCode >= 400 && statusCode < 500;
    }

    public boolean isServerError() {
        return statusCode >= 500 && statusCode < 600;
    }

    public boolean hasError() {
        return error.isPresent();
    }

    public Optional<String> getHeader(String name) {
        List<String> values = headers.get(name);
        return values != null && !values.isEmpty()
            ? Optional.of(values.get(0))
            : Optional.empty();
    }

    @Override
    public String toString() {
        if (hasError()) {
            return "TestResponse{error=" + error.get().getMessage() + "}";
        }
        return "TestResponse{statusCode=" + statusCode +
               ", responseTime=" + responseTimeMs + "ms" +
               ", bodyLength=" + (body != null ? body.length() : 0) + "}";
    }

    public static class Builder {
        private int statusCode;
        private Map<String, List<String>> headers;
        private String body;
        private long responseTimeMs;
        private Exception error;

        public Builder statusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        public Builder headers(Map<String, List<String>> headers) {
            this.headers = headers;
            return this;
        }

        public Builder addHeader(String key, String value) {
            if (this.headers == null) {
                this.headers = new LinkedHashMap<>();
            }
            this.headers.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
            return this;
        }

        public Builder body(String body) {
            this.body = body;
            return this;
        }

        public Builder responseTimeMs(long responseTimeMs) {
            this.responseTimeMs = responseTimeMs;
            return this;
        }

        public Builder error(Exception error) {
            this.error = error;
            return this;
        }

        public TestResponse build() {
            return new TestResponse(this);
        }
    }
}
