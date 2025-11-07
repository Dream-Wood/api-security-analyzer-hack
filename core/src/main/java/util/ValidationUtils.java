package util;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Утилитные методы для логики валидации.
 * Предоставляет вспомогательные функции для проверки HTTP кодов состояния,
 * JSON схем и обработки путей API.
 */
public final class ValidationUtils {

    private ValidationUtils() {
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Проверяет, соответствует ли строка шаблону HTTP кода состояния 2xx (успешные запросы).
     *
     * @param code код состояния HTTP для проверки
     * @return true, если код соответствует шаблону 2xx
     */
    public static boolean is2xxStatusCode(String code) {
        return code != null && code.matches("^2\\d\\d$");
    }

    /**
     * Проверяет, соответствует ли строка шаблону HTTP кода ошибки 4xx или 5xx.
     *
     * @param code код состояния HTTP для проверки
     * @return true, если код соответствует шаблону 4xx или 5xx
     */
    public static boolean isErrorStatusCode(String code) {
        return code != null && code.matches("^[45]\\d\\d$");
    }

    /**
     * Проверяет, является ли JSON схема хорошо определенной.
     * Схема считается хорошо определенной, если содержит поля "type" или "properties".
     *
     * @param schema JSON схема для проверки
     * @return true, если схема хорошо определена
     */
    public static boolean hasWellDefinedSchema(JsonNode schema) {
        if (schema == null) {
            return false;
        }
        String schemaText = schema.toString();
        return schemaText.contains("\"type\"") || schemaText.contains("\"properties\"");
    }

    /**
     * Проверяет, является ли JSON схема типом массива.
     *
     * @param schema JSON схема для проверки
     * @return true, если схема определяет массив
     */
    public static boolean isArraySchema(JsonNode schema) {
        if (schema == null) {
            return false;
        }
        return schema.toString().contains("\"type\":\"array\"");
    }

    /**
     * Проверяет, содержит ли схема массива определение элементов (items).
     *
     * @param schema JSON схема массива для проверки
     * @return true, если определение items присутствует
     */
    public static boolean hasItemsDefinition(JsonNode schema) {
        if (schema == null) {
            return false;
        }
        return schema.toString().contains("\"items\"");
    }

    /**
     * Обрезает строку до максимальной длины, добавляя многоточие при необходимости.
     *
     * @param str строка для обрезки
     * @param maxLength максимальная длина
     * @return обрезанная строка с многоточием или исходная строка
     */
    public static String truncate(String str, int maxLength) {
        if (str == null) {
            return "";
        }
        if (str.length() <= maxLength) {
            return str;
        }
        return str.substring(0, maxLength) + "...";
    }

    /**
     * Проверяет, содержит ли путь параметры пути (в фигурных скобках).
     *
     * @param path путь для проверки
     * @return true, если путь содержит параметры вида {param}
     */
    public static boolean hasPathParameters(String path) {
        return path != null && path.contains("{") && path.contains("}");
    }

    /**
     * Извлекает имена параметров пути из строки пути.
     *
     * @param path путь с параметрами
     * @return список имен параметров (без фигурных скобок)
     */
    public static java.util.List<String> extractPathParameterNames(String path) {
        java.util.List<String> params = new java.util.ArrayList<>();
        if (path == null) {
            return params;
        }

        int start = path.indexOf('{');
        while (start != -1) {
            int end = path.indexOf('}', start);
            if (end != -1) {
                params.add(path.substring(start + 1, end));
                start = path.indexOf('{', end);
            } else {
                break;
            }
        }
        return params;
    }
}
