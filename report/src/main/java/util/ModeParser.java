package util;

import report.AnalysisReport;

/**
 * Утилита для парсинга режима анализа из строкового представления.
 *
 * <p>Централизованный парсер для всех модулей (CLI, WebUI),
 * обеспечивающий единообразную обработку режимов анализа.
 *
 * <p>Поддерживаемые режимы:
 * <ul>
 *   <li><b>static</b> - только статический анализ спецификации</li>
 *   <li><b>active</b> - только активное тестирование безопасности</li>
 *   <li><b>both, combined</b> - статический + активный анализ</li>
 *   <li><b>contract</b> - валидация контракта (fuzzing)</li>
 *   <li><b>full, all</b> - полный анализ (static + active + contract)</li>
 * </ul>
 *
 * @since 1.0
 */
public final class ModeParser {

    private ModeParser() {
        // Утилитный класс - запретить создание экземпляров
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Парсит строковое представление режима анализа в enum {@link AnalysisReport.AnalysisMode}.
     *
     * <p>Парсинг не чувствителен к регистру. Null и пустая строка трактуются как "static".
     *
     * @param mode строковое представление режима (case-insensitive)
     * @return соответствующий {@link AnalysisReport.AnalysisMode}
     * @throws IllegalArgumentException если режим не распознан
     *
     * @example
     * <pre>
     * ModeParser.parse("static")   → STATIC_ONLY
     * ModeParser.parse("active")   → ACTIVE_ONLY
     * ModeParser.parse("COMBINED") → COMBINED
     * ModeParser.parse(null)       → STATIC_ONLY
     * ModeParser.parse("unknown")  → IllegalArgumentException
     * </pre>
     */
    public static AnalysisReport.AnalysisMode parse(String mode) {
        if (mode == null || mode.trim().isEmpty() || mode.equalsIgnoreCase("static")) {
            return AnalysisReport.AnalysisMode.STATIC_ONLY;
        }

        String normalizedMode = mode.trim().toLowerCase();

        switch (normalizedMode) {
            case "active":
                return AnalysisReport.AnalysisMode.ACTIVE_ONLY;

            case "both":
            case "combined":
                return AnalysisReport.AnalysisMode.COMBINED;

            case "contract":
                return AnalysisReport.AnalysisMode.CONTRACT;

            case "full":
            case "all":
                return AnalysisReport.AnalysisMode.FULL;

            default:
                throw new IllegalArgumentException(
                    String.format("Неизвестный режим анализа: '%s'. " +
                        "Допустимые значения: static, active, both/combined, contract, full/all", mode)
                );
        }
    }

    /**
     * Парсит режим анализа с возвратом значения по умолчанию при ошибке.
     *
     * @param mode строковое представление режима
     * @param defaultMode режим по умолчанию при ошибке парсинга
     * @return распознанный режим или defaultMode
     */
    public static AnalysisReport.AnalysisMode parseOrDefault(String mode, AnalysisReport.AnalysisMode defaultMode) {
        try {
            return parse(mode);
        } catch (IllegalArgumentException e) {
            return defaultMode;
        }
    }

    /**
     * Проверяет, является ли строка валидным режимом анализа.
     *
     * @param mode строковое представление режима
     * @return true если режим валиден, false иначе
     */
    public static boolean isValidMode(String mode) {
        try {
            parse(mode);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
