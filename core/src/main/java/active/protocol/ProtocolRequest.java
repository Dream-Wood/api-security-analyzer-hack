package active.protocol;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Represents a request to interact with an async protocol.
 * Can be used for publish operations or request-reply patterns.
 */
public class ProtocolRequest {

    public enum RequestType {
        PUBLISH,          // One-way publish
        SUBSCRIBE,        // Subscribe to channel
        REQUEST_REPLY,    // Request-reply pattern
        UNSUBSCRIBE       // Unsubscribe from channel
    }

    private final RequestType type;
    private final String channel;
    private final String payload;
    private final String contentType;
    private final Map<String, String> headers;
    private final Map<String, Object> parameters;
    private final int timeoutMs;

    private ProtocolRequest(Builder builder) {
        this.type = builder.type;
        this.channel = builder.channel;
        this.payload = builder.payload;
        this.contentType = builder.contentType;
        this.headers = Collections.unmodifiableMap(new HashMap<>(builder.headers));
        this.parameters = Collections.unmodifiableMap(new HashMap<>(builder.parameters));
        this.timeoutMs = builder.timeoutMs;
    }

    public RequestType getType() {
        return type;
    }

    public String getChannel() {
        return channel;
    }

    public String getPayload() {
        return payload;
    }

    public String getContentType() {
        return contentType;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public Optional<String> getHeader(String name) {
        return Optional.ofNullable(headers.get(name));
    }

    public Map<String, Object> getParameters() {
        return parameters;
    }

    public Optional<Object> getParameter(String key) {
        return Optional.ofNullable(parameters.get(key));
    }

    public int getTimeoutMs() {
        return timeoutMs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private RequestType type = RequestType.PUBLISH;
        private String channel;
        private String payload = "";
        private String contentType = "application/json";
        private Map<String, String> headers = new HashMap<>();
        private Map<String, Object> parameters = new HashMap<>();
        private int timeoutMs = 30000; // 30 seconds default

        public Builder type(RequestType type) {
            this.type = type;
            return this;
        }

        public Builder channel(String channel) {
            this.channel = channel;
            return this;
        }

        public Builder payload(String payload) {
            this.payload = payload;
            return this;
        }

        public Builder contentType(String contentType) {
            this.contentType = contentType;
            return this;
        }

        public Builder header(String name, String value) {
            this.headers.put(name, value);
            return this;
        }

        public Builder headers(Map<String, String> headers) {
            this.headers.putAll(headers);
            return this;
        }

        public Builder parameter(String key, Object value) {
            this.parameters.put(key, value);
            return this;
        }

        public Builder parameters(Map<String, Object> parameters) {
            this.parameters.putAll(parameters);
            return this;
        }

        public Builder timeoutMs(int timeoutMs) {
            this.timeoutMs = timeoutMs;
            return this;
        }

        public ProtocolRequest build() {
            if (channel == null || channel.trim().isEmpty()) {
                throw new IllegalArgumentException("Channel cannot be null or empty");
            }
            return new ProtocolRequest(this);
        }
    }

    @Override
    public String toString() {
        return String.format("ProtocolRequest{type=%s, channel='%s', contentType='%s', payloadLength=%d, timeout=%dms}",
                type, channel, contentType, payload.length(), timeoutMs);
    }
}
