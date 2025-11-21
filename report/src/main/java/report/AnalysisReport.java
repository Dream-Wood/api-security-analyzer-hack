package report;

import active.ActiveAnalysisEngine;
import active.discovery.EndpointDiscoveryEngine;
import active.validator.ContractValidationEngine;
import model.ValidationFinding;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Унифицированный отчет о результатах анализа безопасности API.
 *
 * <p>Этот класс объединяет результаты всех типов анализа:
 * <ul>
 *   <li><b>Статический анализ</b> - проверка спецификации на соответствие best practices</li>
 *   <li><b>Активное тестирование</b> - поиск уязвимостей через реальные HTTP запросы</li>
 *   <li><b>Валидация контракта</b> - проверка соответствия реализации API спецификации</li>
 * </ul>
 *
 * <p>Отчет является неизменяемым (immutable) объектом, создаваемым через {@link Builder}.
 * Содержит метаинформацию о процессе анализа (время, режим, местоположение спецификации)
 * и результаты каждого типа анализа в виде вложенных объектов.
 *
 * <p>Пример использования:
 * <pre>{@code
 * AnalysisReport report = AnalysisReport.builder()
 *     .specLocation("petstore.yaml")
 *     .specTitle("Petstore API")
 *     .startTime(Instant.now())
 *     .mode(AnalysisMode.FULL)
 *     .staticResult(staticResult)
 *     .activeResult(activeResult)
 *     .contractResult(contractResult)
 *     .endTime(Instant.now())
 *     .build();
 * }</pre>
 *
 * @author API Security Analyzer Team
 * @since 1.0
 * @see AnalysisMode
 * @see StaticAnalysisResult
 * @see ActiveAnalysisResult
 * @see ContractAnalysisResult
 */
public final class AnalysisReport {
    private final String specLocation;
    private final String specTitle;
    private final Instant startTime;
    private final Instant endTime;
    private final AnalysisMode mode;
    private final StaticAnalysisResult staticResult;
    private final ActiveAnalysisResult activeResult;
    private final ContractAnalysisResult contractResult;
    private final DiscoveryAnalysisResult discoveryResult;

    /**
     * Режим анализа API, определяющий какие типы проверок будут выполнены.
     *
     * <p>Различные режимы позволяют оптимизировать процесс анализа в зависимости от целей:
     * <ul>
     *   <li>{@link #STATIC_ONLY} - быстрая проверка спецификации без запросов к API</li>
     *   <li>{@link #ACTIVE_ONLY} - только активное тестирование (требует доступ к API)</li>
     *   <li>{@link #COMBINED} - статический + активный анализ</li>
     *   <li>{@link #CONTRACT} - проверка соответствия реализации контракту</li>
     *   <li>{@link #FULL} - полный анализ со всеми типами проверок</li>
     * </ul>
     */
    public enum AnalysisMode {
        /** Только статический анализ спецификации (без HTTP запросов). */
        STATIC_ONLY,
        /** Только активное тестирование безопасности (требует доступ к API). */
        ACTIVE_ONLY,
        /** Комбинированный режим: статический анализ + активное тестирование. */
        COMBINED,
        /** Проверка соответствия реализации контракту API. */
        CONTRACT,
        /** Полный анализ: статический + активный + валидация контракта. */
        FULL
    }

    private AnalysisReport(Builder builder) {
        this.specLocation = Objects.requireNonNull(builder.specLocation);
        this.specTitle = builder.specTitle;
        this.startTime = Objects.requireNonNull(builder.startTime);
        this.endTime = Objects.requireNonNull(builder.endTime);
        this.mode = Objects.requireNonNull(builder.mode);
        this.staticResult = builder.staticResult;
        this.activeResult = builder.activeResult;
        this.contractResult = builder.contractResult;
        this.discoveryResult = builder.discoveryResult;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getSpecLocation() {
        return specLocation;
    }

    public String getSpecTitle() {
        return specTitle;
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

    public ContractAnalysisResult getContractResult() {
        return contractResult;
    }

    public DiscoveryAnalysisResult getDiscoveryResult() {
        return discoveryResult;
    }

    public boolean hasStaticResults() {
        return staticResult != null;
    }

    public boolean hasActiveResults() {
        return activeResult != null;
    }

    public boolean hasContractResults() {
        return contractResult != null;
    }

    public boolean hasDiscoveryResults() {
        return discoveryResult != null;
    }

    public int getTotalIssueCount() {
        int count = 0;
        if (staticResult != null) {
            count += staticResult.getFindings().size();
        }
        if (activeResult != null && activeResult.getReport() != null) {
            count += activeResult.getReport().getTotalVulnerabilityCount();
        }
        if (contractResult != null && !contractResult.hasError() && contractResult.getReport() != null) {
            count += contractResult.getReport().getTotalDivergences();
        }
        if (discoveryResult != null && !discoveryResult.hasError() && discoveryResult.getReport() != null) {
            count += discoveryResult.getReport().getTotalCount();
        }
        return count;
    }

    /**
     * Результаты статического анализа спецификации API.
     *
     * <p>Содержит информацию о проблемах, обнаруженных при анализе спецификации
     * без выполнения реальных запросов к API. Включает:
     * <ul>
     *   <li>Сообщения о проблемах парсинга спецификации</li>
     *   <li>Список обнаруженных проблем безопасности и соответствия стандартам</li>
     *   <li>Сообщение об ошибке, если анализ не удалось выполнить</li>
     * </ul>
     *
     * <p>Объект является неизменяемым (immutable).
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
     * Результаты активного тестирования безопасности API.
     *
     * <p>Содержит информацию об уязвимостях, обнаруженных при выполнении
     * реальных HTTP запросов к API. Включает результаты работы различных
     * сканеров безопасности:
     * <ul>
     *   <li>SQL Injection сканер</li>
     *   <li>XSS (Cross-Site Scripting) сканер</li>
     *   <li>BOLA (Broken Object Level Authorization) сканер</li>
     *   <li>Authentication bypass сканер</li>
     *   <li>И другие сканеры безопасности</li>
     * </ul>
     *
     * <p>Объект является неизменяемым (immutable).
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

    /**
     * Результаты валидации соответствия реализации API контракту (спецификации).
     *
     * <p>Содержит информацию о расхождениях между тем, что описано в спецификации,
     * и тем, как API фактически работает. Проверяет:
     * <ul>
     *   <li>Соответствие структуры ответов схемам из спецификации</li>
     *   <li>Корректность HTTP статус-кодов</li>
     *   <li>Наличие обязательных полей в ответах</li>
     *   <li>Соответствие типов данных</li>
     *   <li>Дополнительные/отсутствующие поля</li>
     * </ul>
     *
     * <p>Объект является неизменяемым (immutable).
     */
    public static final class ContractAnalysisResult {
        private final ContractValidationEngine.ContractValidationReport report;
        private final String errorMessage;

        public ContractAnalysisResult(ContractValidationEngine.ContractValidationReport report,
                                     String errorMessage) {
            this.report = report;
            this.errorMessage = errorMessage;
        }

        public ContractValidationEngine.ContractValidationReport getReport() {
            return report;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public boolean hasError() {
            return errorMessage != null;
        }
    }

    /**
     * Результаты обнаружения незадокументированных эндпоинтов.
     *
     * <p>Содержит информацию об API эндпоинтах, которые существуют в реальной
     * реализации, но не описаны в спецификации. Использует различные стратегии
     * обнаружения:
     * <ul>
     *   <li>Top-Down - исследование от корня к листьям</li>
     *   <li>Bottom-Up - углубление от известных эндпоинтов</li>
     *   <li>Hybrid - комбинация обоих подходов</li>
     * </ul>
     *
     * <p>Каждый найденный эндпоинт содержит:
     * <ul>
     *   <li>Метод и путь эндпоинта</li>
     *   <li>HTTP статус код ответа</li>
     *   <li>Уровень серьезности находки</li>
     *   <li>Метод обнаружения</li>
     *   <li>Причину идентификации как существующего эндпоинта</li>
     * </ul>
     *
     * <p>Объект является неизменяемым (immutable).
     */
    public static final class DiscoveryAnalysisResult {
        private final EndpointDiscoveryEngine.DiscoveryReport report;
        private final String errorMessage;

        public DiscoveryAnalysisResult(EndpointDiscoveryEngine.DiscoveryReport report,
                                      String errorMessage) {
            this.report = report;
            this.errorMessage = errorMessage;
        }

        public EndpointDiscoveryEngine.DiscoveryReport getReport() {
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
        private String specTitle;
        private Instant startTime;
        private Instant endTime;
        private AnalysisMode mode;
        private StaticAnalysisResult staticResult;
        private ActiveAnalysisResult activeResult;
        private ContractAnalysisResult contractResult;
        private DiscoveryAnalysisResult discoveryResult;

        public Builder specLocation(String specLocation) {
            this.specLocation = specLocation;
            return this;
        }

        public Builder specTitle(String specTitle) {
            this.specTitle = specTitle;
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

        public Builder contractResult(ContractAnalysisResult contractResult) {
            this.contractResult = contractResult;
            return this;
        }

        public Builder discoveryResult(DiscoveryAnalysisResult discoveryResult) {
            this.discoveryResult = discoveryResult;
            return this;
        }

        public AnalysisReport build() {
            return new AnalysisReport(this);
        }
    }
}
