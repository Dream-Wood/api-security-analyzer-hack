package active.protocol;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Configuration for connecting to an async protocol (Kafka, MQTT, WebSocket, etc.).
 * Contains protocol-specific settings like broker URLs, credentials, timeouts, etc.
 */
public class ProtocolConfig {

    private final String protocol;
    private final String url;
    private final Map<String, String> credentials;
    private final Map<String, Object> properties;
    private final int connectionTimeoutMs;
    private final int operationTimeoutMs;
    private final boolean enableSsl;
    private final Map<String, String> sslProperties;

    private ProtocolConfig(Builder builder) {
        this.protocol = builder.protocol;
        this.url = builder.url;
        this.credentials = Collections.unmodifiableMap(new HashMap<>(builder.credentials));
        this.properties = Collections.unmodifiableMap(new HashMap<>(builder.properties));
        this.connectionTimeoutMs = builder.connectionTimeoutMs;
        this.operationTimeoutMs = builder.operationTimeoutMs;
        this.enableSsl = builder.enableSsl;
        this.sslProperties = Collections.unmodifiableMap(new HashMap<>(builder.sslProperties));
    }

    public String getProtocol() {
        return protocol;
    }

    public String getUrl() {
        return url;
    }

    public Map<String, String> getCredentials() {
        return credentials;
    }

    public Optional<String> getCredential(String key) {
        return Optional.ofNullable(credentials.get(key));
    }

    public Optional<String> getUsername() {
        return getCredential("username");
    }

    public Optional<String> getPassword() {
        return getCredential("password");
    }

    public Optional<String> getApiKey() {
        return getCredential("apiKey");
    }

    public Map<String, Object> getProperties() {
        return properties;
    }

    public Optional<Object> getProperty(String key) {
        return Optional.ofNullable(properties.get(key));
    }

    public int getConnectionTimeoutMs() {
        return connectionTimeoutMs;
    }

    public int getOperationTimeoutMs() {
        return operationTimeoutMs;
    }

    public boolean isEnableSsl() {
        return enableSsl;
    }

    public Map<String, String> getSslProperties() {
        return sslProperties;
    }

    public Optional<String> getSslProperty(String key) {
        return Optional.ofNullable(sslProperties.get(key));
    }

    public static Builder builder(String protocol) {
        return new Builder(protocol);
    }

    public static class Builder {
        private final String protocol;
        private String url;
        private Map<String, String> credentials = new HashMap<>();
        private Map<String, Object> properties = new HashMap<>();
        private int connectionTimeoutMs = 30000; // 30 seconds
        private int operationTimeoutMs = 30000;  // 30 seconds
        private boolean enableSsl = false;
        private Map<String, String> sslProperties = new HashMap<>();

        public Builder(String protocol) {
            if (protocol == null || protocol.trim().isEmpty()) {
                throw new IllegalArgumentException("Protocol cannot be null or empty");
            }
            this.protocol = protocol;
        }

        public Builder url(String url) {
            this.url = url;
            return this;
        }

        public Builder credential(String key, String value) {
            this.credentials.put(key, value);
            return this;
        }

        public Builder credentials(Map<String, String> credentials) {
            this.credentials.putAll(credentials);
            return this;
        }

        public Builder username(String username) {
            this.credentials.put("username", username);
            return this;
        }

        public Builder password(String password) {
            this.credentials.put("password", password);
            return this;
        }

        public Builder apiKey(String apiKey) {
            this.credentials.put("apiKey", apiKey);
            return this;
        }

        public Builder property(String key, Object value) {
            this.properties.put(key, value);
            return this;
        }

        public Builder properties(Map<String, Object> properties) {
            this.properties.putAll(properties);
            return this;
        }

        public Builder connectionTimeoutMs(int timeoutMs) {
            this.connectionTimeoutMs = timeoutMs;
            return this;
        }

        public Builder operationTimeoutMs(int timeoutMs) {
            this.operationTimeoutMs = timeoutMs;
            return this;
        }

        public Builder enableSsl(boolean enableSsl) {
            this.enableSsl = enableSsl;
            return this;
        }

        public Builder sslProperty(String key, String value) {
            this.sslProperties.put(key, value);
            return this;
        }

        public Builder sslProperties(Map<String, String> sslProperties) {
            this.sslProperties.putAll(sslProperties);
            return this;
        }

        public ProtocolConfig build() {
            if (url == null || url.trim().isEmpty()) {
                throw new IllegalArgumentException("URL cannot be null or empty");
            }
            return new ProtocolConfig(this);
        }
    }

    @Override
    public String toString() {
        return String.format("ProtocolConfig{protocol='%s', url='%s', ssl=%s, connectionTimeout=%dms, operationTimeout=%dms}",
                protocol, url, enableSsl, connectionTimeoutMs, operationTimeoutMs);
    }
}
