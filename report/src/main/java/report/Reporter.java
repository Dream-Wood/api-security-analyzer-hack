package report;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * Интерфейс для генерации отчетов о результатах анализа в различных форматах.
 *
 * <p>Каждая реализация этого интерфейса отвечает за генерацию отчета в конкретном формате
 * (консоль, JSON, PDF и т.д.). Отчет формируется на основе унифицированного объекта
 * {@link AnalysisReport}, который содержит результаты всех типов анализа.
 *
 * <p>Реализации должны корректно обрабатывать различные типы анализа:
 * <ul>
 *   <li>Статический анализ спецификации</li>
 *   <li>Активное тестирование безопасности</li>
 *   <li>Валидация соответствия контракту</li>
 * </ul>
 *
 * <p>Пример использования:
 * <pre>{@code
 * AnalysisReport report = analyzer.analyze(specLocation);
 * Reporter reporter = ReporterFactory.createReporter(ReportFormat.CONSOLE);
 * try (PrintWriter writer = new PrintWriter(System.out)) {
 *     reporter.generate(report, writer);
 * }
 * }</pre>
 *
 * @author API Security Analyzer Team
 * @since 1.0
 * @see AnalysisReport
 * @see ReporterFactory
 */
public interface Reporter {

    /**
     * Генерирует отчет на основе результатов анализа.
     *
     * <p>Метод должен корректно обрабатывать все разделы отчета:
     * <ul>
     *   <li>Метаинформацию (местоположение спецификации, время анализа, режим)</li>
     *   <li>Результаты статического анализа (если присутствуют)</li>
     *   <li>Результаты активного тестирования (если присутствуют)</li>
     *   <li>Результаты валидации контракта (если присутствуют)</li>
     *   <li>Итоговую сводку</li>
     * </ul>
     *
     * @param report объект унифицированного отчета о результатах анализа
     * @param writer поток вывода для записи отчета
     * @throws IOException если возникла ошибка при записи отчета
     * @throws NullPointerException если {@code report} или {@code writer} равны null
     */
    void generate(AnalysisReport report, PrintWriter writer) throws IOException;

    /**
     * Возвращает формат отчета, поддерживаемый данным генератором.
     *
     * @return формат отчета
     */
    ReportFormat getFormat();
}
