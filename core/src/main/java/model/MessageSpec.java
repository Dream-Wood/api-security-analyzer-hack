package model;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;

/**
 * Represents an AsyncAPI message with its schema and metadata.
 */
public final class MessageSpec {
    private final String name;
    private final String title;
    private final String summary;
    private final String description;
    private final Optional<JsonNode> payloadSchema;
    private final Optional<JsonNode> headersSchema;
    private final String contentType;
    private final List<String> tags;
    private final Map<String, Object> bindings;

    private MessageSpec(Builder builder) {
        this.name = builder.name;
        this.title = builder.title;
        this.summary = builder.summary;
        this.description = builder.description;
        this.payloadSchema = builder.payloadSchema != null ? builder.payloadSchema : Optional.empty();
        this.headersSchema = builder.headersSchema != null ? builder.headersSchema : Optional.empty();
        this.contentType = builder.contentType;
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

    public String getName() {
        return name;
    }

    public String getTitle() {
        return title;
    }

    public String getSummary() {
        return summary;
    }

    public String getDescription() {
        return description;
    }

    public Optional<JsonNode> getPayloadSchema() {
        return payloadSchema;
    }

    public Optional<JsonNode> getHeadersSchema() {
        return headersSchema;
    }

    public String getContentType() {
        return contentType;
    }

    public List<String> getTags() {
        return tags;
    }

    public Map<String, Object> getBindings() {
        return bindings;
    }

    public boolean hasPayloadSchema() {
        return payloadSchema.isPresent();
    }

    public boolean hasHeadersSchema() {
        return headersSchema.isPresent();
    }

    @Override
    public String toString() {
        return "MessageSpec{" +
                "name='" + name + '\'' +
                ", title='" + title + '\'' +
                ", contentType='" + contentType + '\'' +
                ", hasPayload=" + hasPayloadSchema() +
                '}';
    }

    public static class Builder {
        private String name;
        private String title;
        private String summary;
        private String description;
        private Optional<JsonNode> payloadSchema;
        private Optional<JsonNode> headersSchema;
        private String contentType;
        private List<String> tags;
        private Map<String, Object> bindings;

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder title(String title) {
            this.title = title;
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

        public Builder payloadSchema(Optional<JsonNode> payloadSchema) {
            this.payloadSchema = payloadSchema;
            return this;
        }

        public Builder headersSchema(Optional<JsonNode> headersSchema) {
            this.headersSchema = headersSchema;
            return this;
        }

        public Builder contentType(String contentType) {
            this.contentType = contentType;
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

        public MessageSpec build() {
            return new MessageSpec(this);
        }
    }
}
