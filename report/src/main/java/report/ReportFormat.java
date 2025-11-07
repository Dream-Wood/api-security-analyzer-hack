package report;

/**
 * Поддерживаемые форматы вывода отчетов о результатах анализа.
 *
 * <p>Каждый формат предназначен для определенного случая использования:
 * <ul>
 *   <li>{@link #CONSOLE} - интерактивный вывод в консоль с цветами для быстрого анализа</li>
 *   <li>{@link #JSON} - структурированный формат для программной обработки и интеграции с CI/CD</li>
 *   <li>{@link #PDF} - подробный отчет с графиками для документирования и презентации</li>
 * </ul>
 *
 * @author API Security Analyzer Team
 * @since 1.0
 */
public enum ReportFormat {
    /**
     * Консольный вывод с ANSI цветами и форматированием.
     * Оптимален для интерактивной работы и быстрого анализа результатов.
     */
    CONSOLE("Console output with colors"),

    /**
     * JSON формат для программной обработки результатов.
     * Идеален для интеграции с системами CI/CD и автоматизации.
     */
    JSON("JSON format"),

    /**
     * PDF отчет с графиками и детальным анализом.
     * Подходит для документирования, презентаций и архивирования результатов.
     * Включает таблицу содержания, графики распределения уязвимостей и базу знаний.
     */
    PDF("PDF report with charts and detailed analysis");

    private final String description;

    ReportFormat(String description) {
        this.description = description;
    }

    /**
     * Возвращает описание формата отчета.
     *
     * @return текстовое описание формата
     */
    public String getDescription() {
        return description;
    }
}
