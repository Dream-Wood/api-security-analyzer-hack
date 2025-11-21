package active.protocol;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Represents a message in async protocols (Kafka, MQTT, WebSocket, etc.).
 * Used for both publishing and subscribing operations.
 */
public class ProtocolMessage {

    private final String channel;
    private final String payload;
    private final String contentType;
    private final Map<String, String> headers;
    private final Map<String, Object> metadata;
    private final long timestamp;

    private ProtocolMessage(Builder builder) {
        this.channel = builder.channel;
        this.payload = builder.payload;
        this.contentType = builder.contentType;
        this.headers = Collections.unmodifiableMap(new HashMap<>(builder.headers));
        this.metadata = Collections.unmodifiableMap(new HashMap<>(builder.metadata));
        this.timestamp = builder.timestamp;
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

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public Optional<Object> getMetadataValue(String key) {
        return Optional.ofNullable(metadata.get(key));
    }

    public long getTimestamp() {
        return timestamp;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String channel;
        private String payload = "";
        private String contentType = "application/json";
        private Map<String, String> headers = new HashMap<>();
        private Map<String, Object> metadata = new HashMap<>();
        private long timestamp = System.currentTimeMillis();

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

        public Builder metadata(String key, Object value) {
            this.metadata.put(key, value);
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            this.metadata.putAll(metadata);
            return this;
        }

        public Builder timestamp(long timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public ProtocolMessage build() {
            if (channel == null || channel.trim().isEmpty()) {
                throw new IllegalArgumentException("Channel cannot be null or empty");
            }
            return new ProtocolMessage(this);
        }
    }

    @Override
    public String toString() {
        return String.format("ProtocolMessage{channel='%s', contentType='%s', payloadLength=%d, headers=%d, timestamp=%d}",
                channel, contentType, payload.length(), headers.size(), timestamp);
    }
}
