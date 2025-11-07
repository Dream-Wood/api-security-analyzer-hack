package model;

import java.util.*;

/**
 * Represents an AsyncAPI server (message broker, WebSocket endpoint, etc.).
 */
public final class ServerSpec {
    private final String name;
    private final String url;
    private final String protocol;
    private final String protocolVersion;
    private final String description;
    private final List<String> securitySchemes;
    private final Map<String, Object> variables;
    private final Map<String, Object> bindings;

    private ServerSpec(Builder builder) {
        this.name = Objects.requireNonNull(builder.name, "name cannot be null");
        this.url = Objects.requireNonNull(builder.url, "url cannot be null");
        this.protocol = Objects.requireNonNull(builder.protocol, "protocol cannot be null");
        this.protocolVersion = builder.protocolVersion;
        this.description = builder.description;
        this.securitySchemes = builder.securitySchemes != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.securitySchemes))
            : Collections.emptyList();
        this.variables = builder.variables != null
            ? Collections.unmodifiableMap(new HashMap<>(builder.variables))
            : Collections.emptyMap();
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

    public String getUrl() {
        return url;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getProtocolVersion() {
        return protocolVersion;
    }

    public String getDescription() {
        return description;
    }

    public List<String> getSecuritySchemes() {
        return securitySchemes;
    }

    public Map<String, Object> getVariables() {
        return variables;
    }

    public Map<String, Object> getBindings() {
        return bindings;
    }

    public boolean requiresAuthentication() {
        return !securitySchemes.isEmpty();
    }

    public boolean isSecure() {
        String lowerProtocol = protocol.toLowerCase();
        return lowerProtocol.contains("wss")
            || lowerProtocol.contains("https")
            || lowerProtocol.contains("mqtts")
            || lowerProtocol.contains("amqps")
            || lowerProtocol.contains("kafka-secure");
    }

    @Override
    public String toString() {
        return "ServerSpec{" +
                "name='" + name + '\'' +
                ", url='" + url + '\'' +
                ", protocol='" + protocol + '\'' +
                ", secure=" + isSecure() +
                '}';
    }

    public static class Builder {
        private String name;
        private String url;
        private String protocol;
        private String protocolVersion;
        private String description;
        private List<String> securitySchemes;
        private Map<String, Object> variables;
        private Map<String, Object> bindings;

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder url(String url) {
            this.url = url;
            return this;
        }

        public Builder protocol(String protocol) {
            this.protocol = protocol;
            return this;
        }

        public Builder protocolVersion(String protocolVersion) {
            this.protocolVersion = protocolVersion;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder securitySchemes(List<String> securitySchemes) {
            this.securitySchemes = securitySchemes;
            return this;
        }

        public Builder variables(Map<String, Object> variables) {
            this.variables = variables;
            return this;
        }

        public Builder bindings(Map<String, Object> bindings) {
            this.bindings = bindings;
            return this;
        }

        public ServerSpec build() {
            return new ServerSpec(this);
        }
    }
}
