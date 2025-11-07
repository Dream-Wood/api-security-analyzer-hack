package model;

import java.util.*;

/**
 * Represents an AsyncAPI channel (topic, queue, etc.).
 */
public final class ChannelSpec {
    private final String name;
    private final String description;
    private final Optional<AsyncOperationSpec> publishOperation;
    private final Optional<AsyncOperationSpec> subscribeOperation;
    private final List<String> servers;
    private final Map<String, Object> bindings;
    private final Map<String, Object> parameters;

    private ChannelSpec(Builder builder) {
        this.name = Objects.requireNonNull(builder.name, "name cannot be null");
        this.description = builder.description;
        this.publishOperation = builder.publishOperation != null
            ? builder.publishOperation
            : Optional.empty();
        this.subscribeOperation = builder.subscribeOperation != null
            ? builder.subscribeOperation
            : Optional.empty();
        this.servers = builder.servers != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.servers))
            : Collections.emptyList();
        this.bindings = builder.bindings != null
            ? Collections.unmodifiableMap(new HashMap<>(builder.bindings))
            : Collections.emptyMap();
        this.parameters = builder.parameters != null
            ? Collections.unmodifiableMap(new HashMap<>(builder.parameters))
            : Collections.emptyMap();
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public Optional<AsyncOperationSpec> getPublishOperation() {
        return publishOperation;
    }

    public Optional<AsyncOperationSpec> getSubscribeOperation() {
        return subscribeOperation;
    }

    public List<String> getServers() {
        return servers;
    }

    public Map<String, Object> getBindings() {
        return bindings;
    }

    public Map<String, Object> getParameters() {
        return parameters;
    }

    public boolean hasPublishOperation() {
        return publishOperation.isPresent();
    }

    public boolean hasSubscribeOperation() {
        return subscribeOperation.isPresent();
    }

    public boolean hasSecuritySchemes() {
        return (publishOperation.isPresent() && publishOperation.get().requiresAuthentication())
            || (subscribeOperation.isPresent() && subscribeOperation.get().requiresAuthentication());
    }

    public List<AsyncOperationSpec> getAllOperations() {
        List<AsyncOperationSpec> operations = new ArrayList<>();
        publishOperation.ifPresent(operations::add);
        subscribeOperation.ifPresent(operations::add);
        return operations;
    }

    @Override
    public String toString() {
        return "ChannelSpec{" +
                "name='" + name + '\'' +
                ", hasPublish=" + hasPublishOperation() +
                ", hasSubscribe=" + hasSubscribeOperation() +
                '}';
    }

    public static class Builder {
        private String name;
        private String description;
        private Optional<AsyncOperationSpec> publishOperation;
        private Optional<AsyncOperationSpec> subscribeOperation;
        private List<String> servers;
        private Map<String, Object> bindings;
        private Map<String, Object> parameters;

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder publishOperation(Optional<AsyncOperationSpec> publishOperation) {
            this.publishOperation = publishOperation;
            return this;
        }

        public Builder subscribeOperation(Optional<AsyncOperationSpec> subscribeOperation) {
            this.subscribeOperation = subscribeOperation;
            return this;
        }

        public Builder servers(List<String> servers) {
            this.servers = servers;
            return this;
        }

        public Builder bindings(Map<String, Object> bindings) {
            this.bindings = bindings;
            return this;
        }

        public Builder parameters(Map<String, Object> parameters) {
            this.parameters = parameters;
            return this;
        }

        public ChannelSpec build() {
            return new ChannelSpec(this);
        }
    }
}
