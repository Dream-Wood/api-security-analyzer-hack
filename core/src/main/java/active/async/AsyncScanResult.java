package active.async;

import model.AsyncOperationSpec;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Result of scanning an AsyncAPI operation with an async vulnerability scanner.
 * Contains information about the scanned operation and any vulnerabilities found.
 */
public class AsyncScanResult {

    private final String scannerName;
    private final AsyncOperationSpec operation;
    private final boolean success;
    private final List<AsyncVulnerabilityReport> vulnerabilities;
    private final String errorMessage;
    private final long durationMs;
    private final int requestCount;

    private AsyncScanResult(Builder builder) {
        this.scannerName = builder.scannerName;
        this.operation = builder.operation;
        this.success = builder.success;
        this.vulnerabilities = Collections.unmodifiableList(new ArrayList<>(builder.vulnerabilities));
        this.errorMessage = builder.errorMessage;
        this.durationMs = builder.durationMs;
        this.requestCount = builder.requestCount;
    }

    public String getScannerName() {
        return scannerName;
    }

    public AsyncOperationSpec getOperation() {
        return operation;
    }

    public boolean isSuccess() {
        return success;
    }

    public List<AsyncVulnerabilityReport> getVulnerabilities() {
        return vulnerabilities;
    }

    public boolean hasVulnerabilities() {
        return !vulnerabilities.isEmpty();
    }

    public int getVulnerabilityCount() {
        return vulnerabilities.size();
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public long getDurationMs() {
        return durationMs;
    }

    public int getRequestCount() {
        return requestCount;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String scannerName;
        private AsyncOperationSpec operation;
        private boolean success = true;
        private List<AsyncVulnerabilityReport> vulnerabilities = new ArrayList<>();
        private String errorMessage;
        private long durationMs;
        private int requestCount;

        public Builder scannerName(String scannerName) {
            this.scannerName = scannerName;
            return this;
        }

        public Builder operation(AsyncOperationSpec operation) {
            this.operation = operation;
            return this;
        }

        public Builder success(boolean success) {
            this.success = success;
            return this;
        }

        public Builder addVulnerability(AsyncVulnerabilityReport vulnerability) {
            this.vulnerabilities.add(vulnerability);
            return this;
        }

        public Builder vulnerabilities(List<AsyncVulnerabilityReport> vulnerabilities) {
            this.vulnerabilities.addAll(vulnerabilities);
            return this;
        }

        public Builder errorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
            return this;
        }

        public Builder durationMs(long durationMs) {
            this.durationMs = durationMs;
            return this;
        }

        public Builder requestCount(int requestCount) {
            this.requestCount = requestCount;
            return this;
        }

        public AsyncScanResult build() {
            if (scannerName == null) {
                throw new IllegalArgumentException("Scanner name cannot be null");
            }
            if (operation == null) {
                throw new IllegalArgumentException("Operation cannot be null");
            }
            return new AsyncScanResult(this);
        }
    }

    @Override
    public String toString() {
        return String.format("AsyncScanResult{scanner='%s', operation='%s/%s', success=%s, vulnerabilities=%d, duration=%dms}",
                scannerName, operation.getChannelName(), operation.getOperationType(),
                success, vulnerabilities.size(), durationMs);
    }
}
