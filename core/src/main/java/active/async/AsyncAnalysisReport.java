package active.async;

import model.Severity;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Report containing results of AsyncAPI active analysis.
 * Aggregates findings from all async vulnerability scanners across all operations.
 */
public class AsyncAnalysisReport {

    private final List<AsyncScanResult> scanResults;
    private final long durationMs;
    private final Instant timestamp;
    private final int totalOperationsScanned;
    private final int totalScannersExecuted;
    private final int totalVulnerabilities;

    public AsyncAnalysisReport(List<AsyncScanResult> scanResults, long durationMs) {
        this.scanResults = Collections.unmodifiableList(new ArrayList<>(scanResults));
        this.durationMs = durationMs;
        this.timestamp = Instant.now();

        // Calculate statistics
        this.totalOperationsScanned = (int) scanResults.stream()
                .map(result -> result.getOperation().getChannelName() + ":" + result.getOperation().getOperationType())
                .distinct()
                .count();

        this.totalScannersExecuted = scanResults.size();

        this.totalVulnerabilities = scanResults.stream()
                .mapToInt(AsyncScanResult::getVulnerabilityCount)
                .sum();
    }

    /**
     * Get all scan results.
     *
     * @return unmodifiable list of scan results
     */
    public List<AsyncScanResult> getScanResults() {
        return scanResults;
    }

    /**
     * Get all vulnerabilities found across all scans.
     *
     * @return list of all vulnerabilities
     */
    public List<AsyncVulnerabilityReport> getAllVulnerabilities() {
        return scanResults.stream()
                .flatMap(result -> result.getVulnerabilities().stream())
                .collect(Collectors.toList());
    }

    /**
     * Get vulnerabilities grouped by severity.
     *
     * @return map of severity to vulnerabilities
     */
    public Map<Severity, List<AsyncVulnerabilityReport>> getVulnerabilitiesBySeverity() {
        return getAllVulnerabilities().stream()
                .collect(Collectors.groupingBy(AsyncVulnerabilityReport::getSeverity));
    }

    /**
     * Get vulnerabilities of specific severity.
     *
     * @param severity the severity level
     * @return list of vulnerabilities with that severity
     */
    public List<AsyncVulnerabilityReport> getVulnerabilitiesBySeverity(Severity severity) {
        return getAllVulnerabilities().stream()
                .filter(v -> v.getSeverity() == severity)
                .collect(Collectors.toList());
    }

    /**
     * Get vulnerabilities grouped by protocol.
     *
     * @return map of protocol to vulnerabilities
     */
    public Map<String, List<AsyncVulnerabilityReport>> getVulnerabilitiesByProtocol() {
        return getAllVulnerabilities().stream()
                .collect(Collectors.groupingBy(
                        v -> v.getProtocolMetadata().getProtocol()));
    }

    /**
     * Get vulnerabilities grouped by channel.
     *
     * @return map of channel name to vulnerabilities
     */
    public Map<String, List<AsyncVulnerabilityReport>> getVulnerabilitiesByChannel() {
        return getAllVulnerabilities().stream()
                .collect(Collectors.groupingBy(
                        v -> v.getProtocolMetadata().getChannel()));
    }

    /**
     * Get vulnerabilities grouped by type.
     *
     * @return map of vulnerability type to count
     */
    public Map<AsyncVulnerabilityReport.AsyncVulnerabilityType, Long> getVulnerabilityTypeDistribution() {
        return getAllVulnerabilities().stream()
                .collect(Collectors.groupingBy(
                        AsyncVulnerabilityReport::getType,
                        Collectors.counting()));
    }

    /**
     * Get high severity vulnerabilities.
     *
     * @return list of high severity vulnerabilities
     */
    public List<AsyncVulnerabilityReport> getHighSeverityVulnerabilities() {
        return getVulnerabilitiesBySeverity(Severity.HIGH);
    }

    /**
     * Get medium severity vulnerabilities.
     *
     * @return list of medium severity vulnerabilities
     */
    public List<AsyncVulnerabilityReport> getMediumSeverityVulnerabilities() {
        return getVulnerabilitiesBySeverity(Severity.MEDIUM);
    }

    /**
     * Get low severity vulnerabilities.
     *
     * @return list of low severity vulnerabilities
     */
    public List<AsyncVulnerabilityReport> getLowSeverityVulnerabilities() {
        return getVulnerabilitiesBySeverity(Severity.LOW);
    }

    /**
     * Get the duration of the analysis in milliseconds.
     *
     * @return duration in ms
     */
    public long getDurationMs() {
        return durationMs;
    }

    /**
     * Get the timestamp when the analysis was completed.
     *
     * @return timestamp
     */
    public Instant getTimestamp() {
        return timestamp;
    }

    /**
     * Get the total number of operations scanned.
     *
     * @return operation count
     */
    public int getTotalOperationsScanned() {
        return totalOperationsScanned;
    }

    /**
     * Get the total number of scanner executions.
     *
     * @return scanner execution count
     */
    public int getTotalScannersExecuted() {
        return totalScannersExecuted;
    }

    /**
     * Get the total number of vulnerabilities found.
     *
     * @return vulnerability count
     */
    public int getTotalVulnerabilities() {
        return totalVulnerabilities;
    }

    /**
     * Check if any vulnerabilities were found.
     *
     * @return true if vulnerabilities exist
     */
    public boolean hasVulnerabilities() {
        return totalVulnerabilities > 0;
    }

    /**
     * Get a summary of the analysis.
     *
     * @return formatted summary string
     */
    public String getSummary() {
        StringBuilder summary = new StringBuilder();
        summary.append("AsyncAPI Active Analysis Report\n");
        summary.append("================================\n");
        summary.append(String.format("Timestamp: %s\n", timestamp));
        summary.append(String.format("Duration: %dms\n", durationMs));
        summary.append(String.format("Operations Scanned: %d\n", totalOperationsScanned));
        summary.append(String.format("Scanner Executions: %d\n", totalScannersExecuted));
        summary.append(String.format("Total Vulnerabilities: %d\n", totalVulnerabilities));

        if (hasVulnerabilities()) {
            summary.append("\nVulnerabilities by Severity:\n");
            summary.append(String.format("  HIGH:   %d\n", getHighSeverityVulnerabilities().size()));
            summary.append(String.format("  MEDIUM: %d\n", getMediumSeverityVulnerabilities().size()));
            summary.append(String.format("  LOW:    %d\n", getLowSeverityVulnerabilities().size()));

            summary.append("\nVulnerabilities by Protocol:\n");
            Map<String, List<AsyncVulnerabilityReport>> byProtocol = getVulnerabilitiesByProtocol();
            for (Map.Entry<String, List<AsyncVulnerabilityReport>> entry : byProtocol.entrySet()) {
                summary.append(String.format("  %s: %d\n", entry.getKey(), entry.getValue().size()));
            }
        }

        return summary.toString();
    }

    @Override
    public String toString() {
        return String.format("AsyncAnalysisReport{operations=%d, scanners=%d, vulnerabilities=%d, duration=%dms}",
                totalOperationsScanned, totalScannersExecuted, totalVulnerabilities, durationMs);
    }
}
