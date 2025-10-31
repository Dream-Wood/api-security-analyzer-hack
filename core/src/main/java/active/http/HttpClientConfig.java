package active.http;

import java.time.Duration;
import java.util.*;

/**
 * Configuration for HTTP clients.
 */
public final class HttpClientConfig {
    private final HttpClient.CryptoProtocol cryptoProtocol;
    private final Duration connectTimeout;
    private final Duration readTimeout;
    private final Duration writeTimeout;
    private final boolean followRedirects;
    private final boolean verifySsl;
    private final Map<String, String> defaultHeaders;
    private final Map<String, Object> customSettings;

    private HttpClientConfig(Builder builder) {
        this.cryptoProtocol = builder.cryptoProtocol != null
            ? builder.cryptoProtocol
            : HttpClient.CryptoProtocol.STANDARD_TLS;
        this.connectTimeout = builder.connectTimeout != null
            ? builder.connectTimeout
            : Duration.ofSeconds(30);
        this.readTimeout = builder.readTimeout != null
            ? builder.readTimeout
            : Duration.ofSeconds(30);
        this.writeTimeout = builder.writeTimeout != null
            ? builder.writeTimeout
            : Duration.ofSeconds(30);
        this.followRedirects = builder.followRedirects;
        this.verifySsl = builder.verifySsl;
        this.defaultHeaders = builder.defaultHeaders != null
            ? Collections.unmodifiableMap(new LinkedHashMap<>(builder.defaultHeaders))
            : Collections.emptyMap();
        this.customSettings = builder.customSettings != null
            ? Collections.unmodifiableMap(new HashMap<>(builder.customSettings))
            : Collections.emptyMap();
    }

    public static Builder builder() {
        return new Builder();
    }

    public HttpClient.CryptoProtocol getCryptoProtocol() {
        return cryptoProtocol;
    }

    public Duration getConnectTimeout() {
        return connectTimeout;
    }

    public Duration getReadTimeout() {
        return readTimeout;
    }

    public Duration getWriteTimeout() {
        return writeTimeout;
    }

    public boolean isFollowRedirects() {
        return followRedirects;
    }

    public boolean isVerifySsl() {
        return verifySsl;
    }

    public Map<String, String> getDefaultHeaders() {
        return defaultHeaders;
    }

    public Map<String, Object> getCustomSettings() {
        return customSettings;
    }

    public Optional<Object> getCustomSetting(String key) {
        return Optional.ofNullable(customSettings.get(key));
    }

    public static class Builder {
        private HttpClient.CryptoProtocol cryptoProtocol;
        private Duration connectTimeout;
        private Duration readTimeout;
        private Duration writeTimeout;
        private boolean followRedirects = true;
        private boolean verifySsl = true;
        private Map<String, String> defaultHeaders;
        private Map<String, Object> customSettings;

        public Builder cryptoProtocol(HttpClient.CryptoProtocol cryptoProtocol) {
            this.cryptoProtocol = cryptoProtocol;
            return this;
        }

        public Builder connectTimeout(Duration connectTimeout) {
            this.connectTimeout = connectTimeout;
            return this;
        }

        public Builder readTimeout(Duration readTimeout) {
            this.readTimeout = readTimeout;
            return this;
        }

        public Builder writeTimeout(Duration writeTimeout) {
            this.writeTimeout = writeTimeout;
            return this;
        }

        public Builder followRedirects(boolean followRedirects) {
            this.followRedirects = followRedirects;
            return this;
        }

        public Builder verifySsl(boolean verifySsl) {
            this.verifySsl = verifySsl;
            return this;
        }

        public Builder defaultHeaders(Map<String, String> defaultHeaders) {
            this.defaultHeaders = defaultHeaders;
            return this;
        }

        public Builder addDefaultHeader(String key, String value) {
            if (this.defaultHeaders == null) {
                this.defaultHeaders = new LinkedHashMap<>();
            }
            this.defaultHeaders.put(key, value);
            return this;
        }

        public Builder customSettings(Map<String, Object> customSettings) {
            this.customSettings = customSettings;
            return this;
        }

        public Builder addCustomSetting(String key, Object value) {
            if (this.customSettings == null) {
                this.customSettings = new HashMap<>();
            }
            this.customSettings.put(key, value);
            return this;
        }

        public HttpClientConfig build() {
            return new HttpClientConfig(this);
        }
    }
}
