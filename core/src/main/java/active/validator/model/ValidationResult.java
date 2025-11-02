package active.validator.model;

import java.time.Instant;
import java.util.*;

/**
 * Result of endpoint validation containing all detected divergences.
 */
public final class ValidationResult {
    private final String endpoint;
    private final String method;
    private final ValidationStatus status;
    private final List<Divergence> divergences;
    private final int totalTests;
    private final Instant timestamp;
    private final Map<String, Object> metadata;

    private ValidationResult(Builder builder) {
        this.endpoint = Objects.requireNonNull(builder.endpoint, "endpoint cannot be null");
        this.method = Objects.requireNonNull(builder.method, "method cannot be null");
        this.status = Objects.requireNonNull(builder.status, "status cannot be null");
        this.divergences = builder.divergences != null
            ? Collections.unmodifiableList(new ArrayList<>(builder.divergences))
            : Collections.emptyList();
        this.totalTests = builder.totalTests;
        this.timestamp = builder.timestamp != null ? builder.timestamp : Instant.now();
        this.metadata = builder.metadata != null
            ? Collections.unmodifiableMap(new HashMap<>(builder.metadata))
            : Collections.emptyMap();
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getEndpoint() {
        return endpoint;
    }

    public String getMethod() {
        return method;
    }

    public ValidationStatus getStatus() {
        return status;
    }

    public List<Divergence> getDivergences() {
        return divergences;
    }

    public int getTotalTests() {
        return totalTests;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public boolean hasDivergences() {
        return !divergences.isEmpty();
    }

    public long getCriticalCount() {
        return divergences.stream()
            .filter(d -> d.getSeverity() == Divergence.Severity.CRITICAL)
            .count();
    }

    public long getHighCount() {
        return divergences.stream()
            .filter(d -> d.getSeverity() == Divergence.Severity.HIGH)
            .count();
    }

    @Override
    public String toString() {
        return String.format("ValidationResult{endpoint='%s %s', status=%s, divergences=%d, tests=%d}",
            method, endpoint, status, divergences.size(), totalTests);
    }

    public enum ValidationStatus {
        PASSED,           // No divergences found
        FAILED,           // Critical divergences found
        WARNING,          // Non-critical divergences found
        ERROR,            // Validation couldn't complete
        NOT_DOCUMENTED    // Endpoint not found in specification
    }

    public static class Builder {
        private String endpoint;
        private String method;
        private ValidationStatus status;
        private List<Divergence> divergences;
        private int totalTests;
        private Instant timestamp;
        private Map<String, Object> metadata;

        public Builder endpoint(String endpoint) {
            this.endpoint = endpoint;
            return this;
        }

        public Builder method(String method) {
            this.method = method;
            return this;
        }

        public Builder status(ValidationStatus status) {
            this.status = status;
            return this;
        }

        public Builder divergences(List<Divergence> divergences) {
            this.divergences = divergences;
            return this;
        }

        public Builder addDivergence(Divergence divergence) {
            if (this.divergences == null) {
                this.divergences = new ArrayList<>();
            }
            this.divergences.add(divergence);
            return this;
        }

        public Builder totalTests(int totalTests) {
            this.totalTests = totalTests;
            return this;
        }

        public Builder timestamp(Instant timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }

        public Builder addMetadata(String key, Object value) {
            if (this.metadata == null) {
                this.metadata = new HashMap<>();
            }
            this.metadata.put(key, value);
            return this;
        }

        public ValidationResult build() {
            return new ValidationResult(this);
        }
    }
}
