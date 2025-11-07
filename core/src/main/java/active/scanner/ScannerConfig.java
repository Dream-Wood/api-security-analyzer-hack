package active.scanner;

import java.util.*;

/**
 * Конфигурация для сканера уязвимостей.
 * Определяет параметры сканирования, такие как интенсивность, таймауты и лимиты тестов.
 */
public final class ScannerConfig {
    private final boolean enabled;
    private final int maxTestsPerEndpoint;
    private final int timeoutSeconds;
    private final ScanIntensity intensity;
    private final int requestDelayMs;
    private final Map<String, Object> customSettings;

    private ScannerConfig(Builder builder) {
        this.enabled = builder.enabled;
        this.maxTestsPerEndpoint = builder.maxTestsPerEndpoint > 0
            ? builder.maxTestsPerEndpoint
            : 50;
        this.timeoutSeconds = builder.timeoutSeconds > 0
            ? builder.timeoutSeconds
            : 30;
        this.intensity = builder.intensity != null ? builder.intensity : ScanIntensity.MEDIUM;
        this.requestDelayMs = builder.requestDelayMs >= 0
            ? builder.requestDelayMs
            : this.intensity.getRequestDelayMs();
        this.customSettings = builder.customSettings != null
            ? Collections.unmodifiableMap(new HashMap<>(builder.customSettings))
            : Collections.emptyMap();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static ScannerConfig defaultConfig() {
        return builder().enabled(true).build();
    }

    public boolean isEnabled() {
        return enabled;
    }

    public int getMaxTestsPerEndpoint() {
        return maxTestsPerEndpoint;
    }

    public int getTimeoutSeconds() {
        return timeoutSeconds;
    }

    public Map<String, Object> getCustomSettings() {
        return customSettings;
    }

    public Optional<Object> getCustomSetting(String key) {
        return Optional.ofNullable(customSettings.get(key));
    }

    public ScanIntensity getIntensity() {
        return intensity;
    }

    public int getRequestDelayMs() {
        return requestDelayMs;
    }

    public static class Builder {
        private boolean enabled = true;
        private int maxTestsPerEndpoint = 50;
        private int timeoutSeconds = 30;
        private ScanIntensity intensity;
        private int requestDelayMs = -1; // -1 means use intensity default
        private Map<String, Object> customSettings;

        public Builder enabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        public Builder maxTestsPerEndpoint(int maxTestsPerEndpoint) {
            this.maxTestsPerEndpoint = maxTestsPerEndpoint;
            return this;
        }

        public Builder timeoutSeconds(int timeoutSeconds) {
            this.timeoutSeconds = timeoutSeconds;
            return this;
        }

        public Builder intensity(ScanIntensity intensity) {
            this.intensity = intensity;
            return this;
        }

        public Builder requestDelayMs(int requestDelayMs) {
            this.requestDelayMs = requestDelayMs;
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

        public ScannerConfig build() {
            return new ScannerConfig(this);
        }
    }
}
