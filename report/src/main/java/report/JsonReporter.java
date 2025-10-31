package report;

import active.ActiveAnalysisEngine;
import active.model.VulnerabilityReport;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import model.ValidationFinding;

import java.io.IOException;
import java.io.PrintWriter;
import java.time.Duration;
import java.util.*;

/**
 * JSON format reporter.
 */
public final class JsonReporter implements Reporter {

    private final ObjectMapper objectMapper;

    public JsonReporter() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        this.objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    @Override
    public void generate(AnalysisReport report, PrintWriter writer) throws IOException {
        Map<String, Object> jsonReport = new LinkedHashMap<>();

        jsonReport.put("specLocation", report.getSpecLocation());
        jsonReport.put("startTime", report.getStartTime().toString());
        jsonReport.put("endTime", report.getEndTime().toString());
        jsonReport.put("durationSeconds",
            Duration.between(report.getStartTime(), report.getEndTime()).getSeconds());
        jsonReport.put("mode", report.getMode().toString());

        // Static analysis
        if (report.hasStaticResults()) {
            jsonReport.put("staticAnalysis", buildStaticSection(report.getStaticResult()));
        }

        // Active analysis
        if (report.hasActiveResults()) {
            jsonReport.put("activeAnalysis", buildActiveSection(report.getActiveResult()));
        }

        // Summary
        jsonReport.put("summary", buildSummary(report));

        String json = objectMapper.writeValueAsString(jsonReport);
        writer.println(json);
    }

    private Map<String, Object> buildStaticSection(AnalysisReport.StaticAnalysisResult result) {
        Map<String, Object> staticSection = new LinkedHashMap<>();

        if (result.hasError()) {
            staticSection.put("error", result.getErrorMessage());
            return staticSection;
        }

        staticSection.put("parsingMessages", result.getParsingMessages());

        List<Map<String, Object>> findings = new ArrayList<>();
        for (ValidationFinding finding : result.getFindings()) {
            Map<String, Object> findingMap = new LinkedHashMap<>();
            findingMap.put("id", finding.getId());
            findingMap.put("type", finding.getType());
            findingMap.put("severity", finding.getSeverity().toString());
            findingMap.put("category", finding.getCategory().toString());
            findingMap.put("path", finding.getPath());
            findingMap.put("method", finding.getMethod());
            findingMap.put("details", finding.getDetails());
            findingMap.put("recommendation", finding.getRecommendation());
            findingMap.put("metadata", finding.getMetadata());
            findings.add(findingMap);
        }
        staticSection.put("findings", findings);
        staticSection.put("findingsCount", findings.size());

        // Summary by severity
        Map<String, Long> bySeverity = new LinkedHashMap<>();
        result.getFindings().stream()
            .collect(java.util.stream.Collectors.groupingBy(
                f -> f.getSeverity().toString(),
                java.util.stream.Collectors.counting()))
            .forEach(bySeverity::put);
        staticSection.put("findingsBySeverity", bySeverity);

        return staticSection;
    }

    private Map<String, Object> buildActiveSection(AnalysisReport.ActiveAnalysisResult result) {
        Map<String, Object> activeSection = new LinkedHashMap<>();

        if (result.hasError()) {
            activeSection.put("error", result.getErrorMessage());
            return activeSection;
        }

        ActiveAnalysisEngine.AnalysisReport activeReport = result.getReport();

        activeSection.put("endpointsScanned", activeReport.getEndpointCount());
        activeSection.put("vulnerableEndpoints", activeReport.getVulnerableEndpointCount());
        activeSection.put("totalVulnerabilities", activeReport.getTotalVulnerabilityCount());
        activeSection.put("durationSeconds", activeReport.getTotalDuration().getSeconds());

        // By severity
        Map<String, Long> bySeverity = new LinkedHashMap<>();
        activeReport.getVulnerabilityCountBySeverity()
            .forEach((severity, count) -> bySeverity.put(severity.toString(), count));
        activeSection.put("vulnerabilitiesBySeverity", bySeverity);

        // By type
        Map<String, Long> byType = new LinkedHashMap<>();
        activeReport.getVulnerabilityCountByType()
            .forEach((type, count) -> byType.put(type.name(), count));
        activeSection.put("vulnerabilitiesByType", byType);

        // Detailed vulnerabilities
        List<Map<String, Object>> vulnerabilities = new ArrayList<>();
        for (ActiveAnalysisEngine.EndpointAnalysisResult endpointResult : activeReport.getEndpointResults()) {
            for (VulnerabilityReport vuln : endpointResult.getAllVulnerabilities()) {
                Map<String, Object> vulnMap = new LinkedHashMap<>();
                vulnMap.put("id", vuln.getId());
                vulnMap.put("type", vuln.getType().name());
                vulnMap.put("typeDisplayName", vuln.getType().getDisplayName());
                vulnMap.put("category", vuln.getType().getCategory());
                vulnMap.put("severity", vuln.getSeverity().toString());
                vulnMap.put("title", vuln.getTitle());
                vulnMap.put("description", vuln.getDescription());
                vulnMap.put("endpoint", endpointResult.endpoint().toString());
                vulnMap.put("reproductionSteps", vuln.getReproductionSteps());
                vulnMap.put("recommendations", vuln.getRecommendations());
                vulnMap.put("evidence", vuln.getEvidence());
                vulnMap.put("discoveredAt", vuln.getDiscoveredAt().toString());
                vulnerabilities.add(vulnMap);
            }
        }
        activeSection.put("vulnerabilities", vulnerabilities);

        return activeSection;
    }

    private Map<String, Object> buildSummary(AnalysisReport report) {
        Map<String, Object> summary = new LinkedHashMap<>();

        summary.put("totalIssues", report.getTotalIssueCount());

        if (report.hasStaticResults() && !report.getStaticResult().hasError()) {
            summary.put("staticIssues", report.getStaticResult().getFindings().size());
        }

        if (report.hasActiveResults() && !report.getActiveResult().hasError()) {
            summary.put("activeVulnerabilities",
                report.getActiveResult().getReport().getTotalVulnerabilityCount());
        }

        return summary;
    }

    @Override
    public ReportFormat getFormat() {
        return ReportFormat.JSON;
    }
}
