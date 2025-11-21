package report;

import active.ActiveAnalysisEngine;
import active.discovery.EndpointDiscoveryEngine;
import active.discovery.model.DiscoveryResult;
import active.model.VulnerabilityReport;
import active.validator.ContractValidationEngine;
import active.validator.model.Divergence;
import active.validator.model.ValidationResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import model.ValidationFinding;

import java.io.IOException;
import java.io.PrintWriter;
import java.time.Duration;
import java.util.*;

/**
 * Генератор отчетов в формате JSON для программной обработки результатов.
 *
 * <p>Создает структурированный JSON-документ со всеми результатами анализа,
 * подходящий для:
 * <ul>
 *   <li>Интеграции с системами CI/CD (Jenkins, GitLab CI, GitHub Actions)</li>
 *   <li>Автоматической обработки и агрегации результатов</li>
 *   <li>Хранения результатов в базах данных</li>
 *   <li>Создания дашбордов и визуализаций</li>
 *   <li>Сравнения результатов между запусками</li>
 * </ul>
 *
 * <p>JSON отчет включает:
 * <ul>
 *   <li>Метаинформацию: название спецификации, местоположение, время, режим</li>
 *   <li>Статический анализ: список всех findings с деталями и группировкой по severity</li>
 *   <li>Активный анализ: список уязвимостей с группировкой по severity и типу</li>
 *   <li>Валидация контракта: список расхождений с группировкой по severity</li>
 *   <li>Итоговую сводку: количество проблем по категориям</li>
 * </ul>
 *
 * <p>Особенности формата:
 * <ul>
 *   <li>Использует pretty-print с отступами для читаемости</li>
 *   <li>Временные метки в ISO-8601 формате (не Unix timestamp)</li>
 *   <li>Все списки представлены как JSON arrays</li>
 *   <li>Использует Jackson для сериализации</li>
 * </ul>
 *
 * <p>Пример использования:
 * <pre>{@code
 * Reporter reporter = new JsonReporter();
 * try (PrintWriter writer = new PrintWriter(new FileWriter("report.json"))) {
 *     reporter.generate(analysisReport, writer);
 * }
 * }</pre>
 *
 * @author API Security Analyzer Team
 * @since 1.0
 * @see Reporter
 * @see AnalysisReport
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

        // Include both title and location for complete information
        if (report.getSpecTitle() != null && !report.getSpecTitle().isEmpty()) {
            jsonReport.put("specTitle", report.getSpecTitle());
        }
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

        // Contract validation
        if (report.hasContractResults()) {
            jsonReport.put("contractValidation", buildContractSection(report.getContractResult()));
        }

        // Endpoint discovery
        if (report.hasDiscoveryResults()) {
            jsonReport.put("endpointDiscovery", buildDiscoverySection(report.getDiscoveryResult()));
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

    private Map<String, Object> buildContractSection(AnalysisReport.ContractAnalysisResult result) {
        Map<String, Object> contractSection = new LinkedHashMap<>();

        if (result.hasError()) {
            contractSection.put("error", result.getErrorMessage());
            return contractSection;
        }

        ContractValidationEngine.ContractValidationReport contractReport = result.getReport();

        contractSection.put("endpointsValidated", contractReport.getTotalEndpoints());
        contractSection.put("totalDivergences", contractReport.getTotalDivergences());
        contractSection.put("criticalDivergences", contractReport.getCriticalDivergences());
        contractSection.put("highDivergences", contractReport.getHighDivergences());
        contractSection.put("fuzzingEnabled", contractReport.isFuzzingEnabled());

        // Statistics
        contractSection.put("statistics", contractReport.getStatistics());

        // By severity
        Map<String, Long> bySeverity = new LinkedHashMap<>();
        contractReport.getDivergencesBySeverity()
            .forEach((severity, divergences) -> bySeverity.put(severity.name(), (long) divergences.size()));
        contractSection.put("divergencesBySeverity", bySeverity);

        // Detailed divergences
        List<Map<String, Object>> divergences = new ArrayList<>();
        for (ValidationResult result1 : contractReport.getResults()) {
            for (Divergence divergence : result1.getDivergences()) {
                Map<String, Object> divMap = new LinkedHashMap<>();
                divMap.put("type", divergence.getType().name());
                divMap.put("severity", divergence.getSeverity().name());
                divMap.put("path", divergence.getPath());
                divMap.put("field", divergence.getField());
                divMap.put("message", divergence.getMessage());
                divMap.put("expectedValue", divergence.getExpectedValue());
                divMap.put("actualValue", divergence.getActualValue());
                divMap.put("metadata", divergence.getMetadata());
                divergences.add(divMap);
            }
        }
        contractSection.put("divergences", divergences);

        return contractSection;
    }

    private Map<String, Object> buildDiscoverySection(AnalysisReport.DiscoveryAnalysisResult result) {
        Map<String, Object> discoverySection = new LinkedHashMap<>();

        if (result.hasError()) {
            discoverySection.put("error", result.getErrorMessage());
            return discoverySection;
        }

        EndpointDiscoveryEngine.DiscoveryReport discoveryReport = result.getReport();

        discoverySection.put("strategy", discoveryReport.getConfig().getStrategy().name());
        discoverySection.put("totalEndpointsFound", discoveryReport.getTotalCount());
        discoverySection.put("criticalFindings", discoveryReport.getCriticalResults().size());
        discoverySection.put("highFindings", discoveryReport.getHighResults().size());
        discoverySection.put("durationSeconds", discoveryReport.getDuration().getSeconds());

        // By severity
        Map<String, Long> bySeverity = new LinkedHashMap<>();
        discoveryReport.getCountBySeverity()
            .forEach((severity, count) -> bySeverity.put(severity.toString(), count));
        discoverySection.put("endpointsBySeverity", bySeverity);

        // By discovery method
        Map<String, Long> byMethod = new LinkedHashMap<>();
        discoveryReport.getCountByMethod()
            .forEach((method, count) -> byMethod.put(method.name(), count));
        discoverySection.put("endpointsByMethod", byMethod);

        // Detailed results
        List<Map<String, Object>> endpoints = new ArrayList<>();
        for (DiscoveryResult discoveryResult : discoveryReport.getResults()) {
            Map<String, Object> endpointMap = new LinkedHashMap<>();
            endpointMap.put("method", discoveryResult.getEndpoint().getMethod());
            endpointMap.put("path", discoveryResult.getEndpoint().getPath());
            endpointMap.put("statusCode", discoveryResult.getStatusCode());
            endpointMap.put("severity", discoveryResult.getSeverity().toString());
            endpointMap.put("discoveryMethod", discoveryResult.getDiscoveryMethod().name());
            endpointMap.put("responseTimeMs", discoveryResult.getResponseTimeMs());
            endpointMap.put("reason", discoveryResult.getReason());
            endpointMap.put("discoveredAt", discoveryResult.getDiscoveredAt().toString());
            endpointMap.put("metadata", discoveryResult.getMetadata());
            endpoints.add(endpointMap);
        }
        discoverySection.put("endpoints", endpoints);

        return discoverySection;
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

        if (report.hasContractResults() && !report.getContractResult().hasError()) {
            summary.put("contractDivergences",
                report.getContractResult().getReport().getTotalDivergences());
        }

        if (report.hasDiscoveryResults() && !report.getDiscoveryResult().hasError()) {
            summary.put("undocumentedEndpoints",
                report.getDiscoveryResult().getReport().getTotalCount());
        }

        return summary;
    }

    @Override
    public ReportFormat getFormat() {
        return ReportFormat.JSON;
    }
}
