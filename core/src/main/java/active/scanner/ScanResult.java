package active.scanner;

import active.model.ApiEndpoint;
import active.model.VulnerabilityReport;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Результат сканирования уязвимостей на эндпоинте API.
 * Содержит информацию о статусе сканирования, найденных уязвимостях и метриках.
 */
public final class ScanResult {
    private final String scannerId;
    private final ApiEndpoint endpoint;
    private final ScanStatus status;
    private final List<VulnerabilityReport> vulnerabilities;
    private final int totalTests;
    private final int failedTests;
    private final Instant startTime;
    private final Instant endTime;
    private final Optional<String> errorMessage;
    private final Map<String, Object> metadata;

    public enum ScanStatus {
        SUCCESS("Scan completed successfully"),
        PARTIAL("Scan completed with some failures"),
        FAILED("Scan failed"),
        SKIPPED("Scan was skipped");

        private final String description;

        ScanStatus(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }

    private ScanResult(Builder builder) {
        this.scannerId = Objects.requireNonNull(builder.scannerId, "scannerId cannot be null");
        this.endpoint = Objects.requireNonNull(builder.endpoint, "endpoint cannot be null");
        this.status = Objects.requireNonNull(builder.status, "status cannot be null");
        this.vulnerabilities = builder.vulnerabilities != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.vulnerabilities))
            : Collections.emptyList();
        this.totalTests = builder.totalTests;
        this.failedTests = builder.failedTests;
        this.startTime = builder.startTime != null ? builder.startTime : Instant.now();
        this.endTime = builder.endTime != null ? builder.endTime : Instant.now();
        this.errorMessage = Optional.ofNullable(builder.errorMessage);
        this.metadata = builder.metadata != null
            ? Collections.unmodifiableMap(new LinkedHashMap<>(builder.metadata))
            : Collections.emptyMap();
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getScannerId() {
        return scannerId;
    }

    public ApiEndpoint getEndpoint() {
        return endpoint;
    }

    public ScanStatus getStatus() {
        return status;
    }

    public List<VulnerabilityReport> getVulnerabilities() {
        return vulnerabilities;
    }

    public int getVulnerabilityCount() {
        return vulnerabilities.size();
    }

    public int getTotalTests() {
        return totalTests;
    }

    public int getFailedTests() {
        return failedTests;
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getEndTime() {
        return endTime;
    }

    public Duration getDuration() {
        return Duration.between(startTime, endTime);
    }

    public Optional<String> getErrorMessage() {
        return errorMessage;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public boolean hasVulnerabilities() {
        return !vulnerabilities.isEmpty();
    }

    public boolean isSuccessful() {
        return status == ScanStatus.SUCCESS || status == ScanStatus.PARTIAL;
    }

    @Override
    public String toString() {
        return "ScanResult{" +
               "scannerId='" + scannerId + '\'' +
               ", endpoint=" + endpoint +
               ", status=" + status +
               ", vulnerabilities=" + vulnerabilities.size() +
               ", duration=" + getDuration().toMillis() + "ms" +
               '}';
    }

    public static class Builder {
        private String scannerId;
        private ApiEndpoint endpoint;
        private ScanStatus status;
        private List<VulnerabilityReport> vulnerabilities;
        private int totalTests;
        private int failedTests;
        private Instant startTime;
        private Instant endTime;
        private String errorMessage;
        private Map<String, Object> metadata;

        public Builder scannerId(String scannerId) {
            this.scannerId = scannerId;
            return this;
        }

        public Builder endpoint(ApiEndpoint endpoint) {
            this.endpoint = endpoint;
            return this;
        }

        public Builder status(ScanStatus status) {
            this.status = status;
            return this;
        }

        public Builder vulnerabilities(List<VulnerabilityReport> vulnerabilities) {
            this.vulnerabilities = vulnerabilities;
            return this;
        }

        public Builder addVulnerability(VulnerabilityReport vulnerability) {
            if (this.vulnerabilities == null) {
                this.vulnerabilities = new ArrayList<>();
            }
            this.vulnerabilities.add(vulnerability);
            return this;
        }

        public Builder totalTests(int totalTests) {
            this.totalTests = totalTests;
            return this;
        }

        public Builder failedTests(int failedTests) {
            this.failedTests = failedTests;
            return this;
        }

        public Builder startTime(Instant startTime) {
            this.startTime = startTime;
            return this;
        }

        public Builder endTime(Instant endTime) {
            this.endTime = endTime;
            return this;
        }

        public Builder errorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }

        public Builder addMetadata(String key, Object value) {
            if (this.metadata == null) {
                this.metadata = new LinkedHashMap<>();
            }
            this.metadata.put(key, value);
            return this;
        }

        public ScanResult build() {
            return new ScanResult(this);
        }
    }
}
