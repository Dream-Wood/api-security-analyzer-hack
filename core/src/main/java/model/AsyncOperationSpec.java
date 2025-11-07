package model;

import java.util.*;

/**
 * Represents an AsyncAPI operation (publish or subscribe).
 */
public final class AsyncOperationSpec {
    private final String channelName;
    private final AsyncOperationType operationType;
    private final String operationId;
    private final String summary;
    private final String description;
    private final List<MessageSpec> messages;
    private final List<String> securitySchemes;
    private final List<String> tags;
    private final Map<String, Object> bindings;

    private AsyncOperationSpec(Builder builder) {
        this.channelName = Objects.requireNonNull(builder.channelName, "channelName cannot be null");
        this.operationType = Objects.requireNonNull(builder.operationType, "operationType cannot be null");
        this.operationId = builder.operationId;
        this.summary = builder.summary;
        this.description = builder.description;
        this.messages = builder.messages != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.messages))
            : Collections.emptyList();
        this.securitySchemes = builder.securitySchemes != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.securitySchemes))
            : Collections.emptyList();
        this.tags = builder.tags != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.tags))
            : Collections.emptyList();
        this.bindings = builder.bindings != null
            ? Collections.unmodifiableMap(new HashMap<>(builder.bindings))
            : Collections.emptyMap();
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getChannelName() {
        return channelName;
    }

    public AsyncOperationType getOperationType() {
        return operationType;
    }

    public String getOperationId() {
        return operationId;
    }

    public String getSummary() {
        return summary;
    }

    public String getDescription() {
        return description;
    }

    public List<MessageSpec> getMessages() {
        return messages;
    }

    public List<String> getSecuritySchemes() {
        return securitySchemes;
    }

    public List<String> getTags() {
        return tags;
    }

    public Map<String, Object> getBindings() {
        return bindings;
    }

    public boolean requiresAuthentication() {
        return !securitySchemes.isEmpty();
    }

    public boolean hasMessages() {
        return !messages.isEmpty();
    }

    @Override
    public String toString() {
        return "AsyncOperationSpec{" +
                "operationType=" + operationType +
                ", channelName='" + channelName + '\'' +
                ", operationId='" + operationId + '\'' +
                ", messages=" + messages.size() +
                '}';
    }

    public static class Builder {
        private String channelName;
        private AsyncOperationType operationType;
        private String operationId;
        private String summary;
        private String description;
        private List<MessageSpec> messages;
        private List<String> securitySchemes;
        private List<String> tags;
        private Map<String, Object> bindings;

        public Builder channelName(String channelName) {
            this.channelName = channelName;
            return this;
        }

        public Builder operationType(AsyncOperationType operationType) {
            this.operationType = operationType;
            return this;
        }

        public Builder operationId(String operationId) {
            this.operationId = operationId;
            return this;
        }

        public Builder summary(String summary) {
            this.summary = summary;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder messages(List<MessageSpec> messages) {
            this.messages = messages;
            return this;
        }

        public Builder securitySchemes(List<String> securitySchemes) {
            this.securitySchemes = securitySchemes;
            return this;
        }

        public Builder tags(List<String> tags) {
            this.tags = tags;
            return this;
        }

        public Builder bindings(Map<String, Object> bindings) {
            this.bindings = bindings;
            return this;
        }

        public AsyncOperationSpec build() {
            return new AsyncOperationSpec(this);
        }
    }
}
