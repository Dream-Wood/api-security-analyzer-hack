package active.protocol;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Represents a response from an async protocol operation.
 * Can contain multiple messages for subscribe operations or single message for request-reply.
 */
public class ProtocolResponse {

    private final boolean success;
    private final int statusCode; // Protocol-specific status code
    private final String statusMessage;
    private final List<ProtocolMessage> messages;
    private final Map<String, Object> metadata;
    private final long durationMs;
    private final Optional<Throwable> error;

    private ProtocolResponse(Builder builder) {
        this.success = builder.success;
        this.statusCode = builder.statusCode;
        this.statusMessage = builder.statusMessage;
        this.messages = Collections.unmodifiableList(new ArrayList<>(builder.messages));
        this.metadata = Collections.unmodifiableMap(new HashMap<>(builder.metadata));
        this.durationMs = builder.durationMs;
        this.error = builder.error;
    }

    public boolean isSuccess() {
        return success;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getStatusMessage() {
        return statusMessage;
    }

    public List<ProtocolMessage> getMessages() {
        return messages;
    }

    public Optional<ProtocolMessage> getFirstMessage() {
        return messages.isEmpty() ? Optional.empty() : Optional.of(messages.get(0));
    }

    public int getMessageCount() {
        return messages.size();
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public Optional<Object> getMetadataValue(String key) {
        return Optional.ofNullable(metadata.get(key));
    }

    public long getDurationMs() {
        return durationMs;
    }

    public Optional<Throwable> getError() {
        return error;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static ProtocolResponse success() {
        return new Builder().success(true).statusCode(0).statusMessage("OK").build();
    }

    public static ProtocolResponse failure(String message) {
        return new Builder().success(false).statusCode(-1).statusMessage(message).build();
    }

    public static ProtocolResponse failure(Throwable error) {
        return new Builder()
                .success(false)
                .statusCode(-1)
                .statusMessage(error.getMessage())
                .error(error)
                .build();
    }

    public static class Builder {
        private boolean success = true;
        private int statusCode = 0;
        private String statusMessage = "OK";
        private List<ProtocolMessage> messages = new ArrayList<>();
        private Map<String, Object> metadata = new HashMap<>();
        private long durationMs = 0;
        private Optional<Throwable> error = Optional.empty();

        public Builder success(boolean success) {
            this.success = success;
            return this;
        }

        public Builder statusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        public Builder statusMessage(String statusMessage) {
            this.statusMessage = statusMessage;
            return this;
        }

        public Builder message(ProtocolMessage message) {
            this.messages.add(message);
            return this;
        }

        public Builder messages(List<ProtocolMessage> messages) {
            this.messages.addAll(messages);
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

        public Builder durationMs(long durationMs) {
            this.durationMs = durationMs;
            return this;
        }

        public Builder error(Throwable error) {
            this.error = Optional.ofNullable(error);
            return this;
        }

        public ProtocolResponse build() {
            return new ProtocolResponse(this);
        }
    }

    @Override
    public String toString() {
        return String.format("ProtocolResponse{success=%s, statusCode=%d, message='%s', messages=%d, duration=%dms}",
                success, statusCode, statusMessage, messages.size(), durationMs);
    }
}
