package util;

/**
 * Общие утилиты для работы со строками в проекте API Security Analyzer.
 *
 * <p>Предоставляет централизованные методы для типичных операций со строками,
 * используемых в CLI, WebUI и других компонентах.
 *
 * @since 1.0
 */
public final class StringUtils {

    private StringUtils() {
        // Утилитный класс - запретить создание экземпляров
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Очищает путь к спецификации от окружающих кавычек и пробелов.
     *
     * <p>Удаляет:
     * <ul>
     *   <li>Ведущие и завершающие пробелы</li>
     *   <li>Двойные кавычки (") в начале и конце</li>
     *   <li>Одинарные кавычки (') в начале и конце</li>
     * </ul>
     *
     * <p>Полезно для обработки пользовательского ввода, где пути могут быть
     * заключены в кавычки (особенно при работе с путями, содержащими пробелы).
     *
     * @param location путь к спецификации (может быть null)
     * @return очищенный путь или null если входная строка была null
     *
     * @example
     * <pre>
     * cleanSpecLocation("  /path/to/spec.yaml  ")  → "/path/to/spec.yaml"
     * cleanSpecLocation("\"C:/My Specs/api.yaml\"") → "C:/My Specs/api.yaml"
     * cleanSpecLocation("'/tmp/spec.json'")        → "/tmp/spec.json"
     * cleanSpecLocation(null)                      → null
     * </pre>
     */
    public static String cleanSpecLocation(String location) {
        if (location == null) {
            return null;
        }

        String cleaned = location.trim();

        // Удаление двойных кавычек
        if (cleaned.startsWith("\"") && cleaned.endsWith("\"") && cleaned.length() >= 2) {
            cleaned = cleaned.substring(1, cleaned.length() - 1);
        }

        // Удаление одинарных кавычек
        if (cleaned.startsWith("'") && cleaned.endsWith("'") && cleaned.length() >= 2) {
            cleaned = cleaned.substring(1, cleaned.length() - 1);
        }

        return cleaned.trim();
    }

    /**
     * Проверяет, является ли строка пустой или null.
     *
     * @param str проверяемая строка
     * @return true если строка null, пустая или содержит только пробелы
     */
    public static boolean isEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }

    /**
     * Проверяет, что строка не пустая и не null.
     *
     * @param str проверяемая строка
     * @return true если строка не null и содержит хотя бы один непробельный символ
     */
    public static boolean isNotEmpty(String str) {
        return !isEmpty(str);
    }

    /**
     * Возвращает строку или значение по умолчанию, если строка пустая.
     *
     * @param str исходная строка
     * @param defaultValue значение по умолчанию
     * @return исходную строку если она не пустая, иначе defaultValue
     */
    public static String defaultIfEmpty(String str, String defaultValue) {
        return isEmpty(str) ? defaultValue : str;
    }

    /**
     * Обрезает строку до указанной максимальной длины, добавляя многоточие.
     *
     * @param str исходная строка
     * @param maxLength максимальная длина (включая многоточие)
     * @return обрезанная строка с "..." или исходная, если она короче maxLength
     */
    public static String truncate(String str, int maxLength) {
        if (str == null || str.length() <= maxLength) {
            return str;
        }

        if (maxLength <= 3) {
            return "...";
        }

        return str.substring(0, maxLength - 3) + "...";
    }

    /**
     * Нормализует путь, заменяя обратные слеши на прямые (Windows → Unix).
     *
     * <p>Полезно для унификации путей в логах и отчетах.
     *
     * @param path исходный путь
     * @return нормализованный путь с прямыми слешами
     */
    public static String normalizePath(String path) {
        return path == null ? null : path.replace('\\', '/');
    }
}
