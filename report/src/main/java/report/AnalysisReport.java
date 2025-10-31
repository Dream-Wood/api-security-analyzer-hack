package report;

import active.ActiveAnalysisEngine;
import model.ValidationFinding;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Unified analysis report containing both static and active analysis results.
 */
public final class AnalysisReport {
    private final String specLocation;
    private final Instant startTime;
    private final Instant endTime;
    private final AnalysisMode mode;
    private final StaticAnalysisResult staticResult;
    private final ActiveAnalysisResult activeResult;

    public enum AnalysisMode {
        STATIC_ONLY,
        ACTIVE_ONLY,
        COMBINED
    }

    private AnalysisReport(Builder builder) {
        this.specLocation = Objects.requireNonNull(builder.specLocation);
        this.startTime = Objects.requireNonNull(builder.startTime);
        this.endTime = Objects.requireNonNull(builder.endTime);
        this.mode = Objects.requireNonNull(builder.mode);
        this.staticResult = builder.staticResult;
        this.activeResult = builder.activeResult;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getSpecLocation() {
        return specLocation;
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getEndTime() {
        return endTime;
    }

    public AnalysisMode getMode() {
        return mode;
    }

    public StaticAnalysisResult getStaticResult() {
        return staticResult;
    }

    public ActiveAnalysisResult getActiveResult() {
        return activeResult;
    }

    public boolean hasStaticResults() {
        return staticResult != null;
    }

    public boolean hasActiveResults() {
        return activeResult != null;
    }

    public int getTotalIssueCount() {
        int count = 0;
        if (staticResult != null) {
            count += staticResult.getFindings().size();
        }
        if (activeResult != null) {
            count += activeResult.getReport().getTotalVulnerabilityCount();
        }
        return count;
    }

    /**
     * Static analysis result wrapper.
     */
    public static final class StaticAnalysisResult {
        private final List<String> parsingMessages;
        private final List<ValidationFinding> findings;
        private final String errorMessage;

        public StaticAnalysisResult(List<String> parsingMessages,
                                   List<ValidationFinding> findings,
                                   String errorMessage) {
            this.parsingMessages = parsingMessages != null
                ? List.copyOf(parsingMessages)
                : Collections.emptyList();
            this.findings = findings != null
                ? List.copyOf(findings)
                : Collections.emptyList();
            this.errorMessage = errorMessage;
        }

        public List<String> getParsingMessages() {
            return parsingMessages;
        }

        public List<ValidationFinding> getFindings() {
            return findings;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public boolean hasError() {
            return errorMessage != null;
        }
    }

    /**
     * Active analysis result wrapper.
     */
    public static final class ActiveAnalysisResult {
        private final ActiveAnalysisEngine.AnalysisReport report;
        private final String errorMessage;

        public ActiveAnalysisResult(ActiveAnalysisEngine.AnalysisReport report,
                                   String errorMessage) {
            this.report = report;
            this.errorMessage = errorMessage;
        }

        public ActiveAnalysisEngine.AnalysisReport getReport() {
            return report;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public boolean hasError() {
            return errorMessage != null;
        }
    }

    public static class Builder {
        private String specLocation;
        private Instant startTime;
        private Instant endTime;
        private AnalysisMode mode;
        private StaticAnalysisResult staticResult;
        private ActiveAnalysisResult activeResult;

        public Builder specLocation(String specLocation) {
            this.specLocation = specLocation;
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

        public Builder mode(AnalysisMode mode) {
            this.mode = mode;
            return this;
        }

        public Builder staticResult(StaticAnalysisResult staticResult) {
            this.staticResult = staticResult;
            return this;
        }

        public Builder activeResult(ActiveAnalysisResult activeResult) {
            this.activeResult = activeResult;
            return this;
        }

        public AnalysisReport build() {
            return new AnalysisReport(this);
        }
    }
}
