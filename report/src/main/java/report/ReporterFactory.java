package report;

/**
 * Фабрика для создания экземпляров генераторов отчетов.
 *
 * <p>Предоставляет централизованный способ создания {@link Reporter} для различных форматов вывода.
 * Поддерживает настройку параметров генерации, таких как использование цветов в консольном выводе.
 *
 * <p>Примеры использования:
 * <pre>{@code
 * // Создание консольного репортера с цветами
 * Reporter consoleReporter = ReporterFactory.createReporter(ReportFormat.CONSOLE, true);
 *
 * // Создание JSON репортера
 * Reporter jsonReporter = ReporterFactory.createReporter(ReportFormat.JSON);
 *
 * // Создание PDF репортера
 * Reporter pdfReporter = ReporterFactory.createReporter(ReportFormat.PDF);
 * }</pre>
 *
 * @author API Security Analyzer Team
 * @since 1.0
 */
public final class ReporterFactory {

    private ReporterFactory() {
        // Утилитный класс - конструктор закрыт
    }

    /**
     * Создает генератор отчетов для указанного формата с настройкой параметров.
     *
     * <p>Параметр {@code useColors} применяется только для консольного формата.
     * Для других форматов этот параметр игнорируется.
     *
     * @param format формат отчета из {@link ReportFormat}
     * @param useColors использовать ли ANSI цвета (применимо только для {@link ReportFormat#CONSOLE})
     * @return экземпляр генератора отчетов для указанного формата
     * @throws NullPointerException если {@code format} равен null
     */
    public static Reporter createReporter(ReportFormat format, boolean useColors) {
        return switch (format) {
            case CONSOLE -> new ConsoleReporter(useColors);
            case JSON -> new JsonReporter();
            case PDF -> new PdfReporter();
        };
    }

    /**
     * Создает генератор отчетов для указанного формата с настройками по умолчанию.
     *
     * <p>Для консольного формата цвета включены по умолчанию.
     *
     * @param format формат отчета из {@link ReportFormat}
     * @return экземпляр генератора отчетов для указанного формата
     * @throws NullPointerException если {@code format} равен null
     */
    public static Reporter createReporter(ReportFormat format) {
        return createReporter(format, true);
    }
}
