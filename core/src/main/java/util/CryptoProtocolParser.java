package util;

import active.http.HttpClient;

/**
 * Утилита для парсинга криптографического протокола из строкового представления.
 *
 * <p>Централизованный парсер для всех модулей (CLI, WebUI),
 * обеспечивающий единообразную обработку криптографических протоколов.
 *
 * <p>Поддерживаемые протоколы:
 * <ul>
 *   <li><b>standard</b> - стандартный TLS 1.2/1.3 (Java native)</li>
 *   <li><b>gost, cryptopro</b> - ГОСТ криптография (CryptoPro JCSP)</li>
 * </ul>
 *
 * <p>По умолчанию используется STANDARD_TLS для максимальной совместимости.
 *
 * @since 1.0
 */
public final class CryptoProtocolParser {

    private CryptoProtocolParser() {
        // Утилитный класс - запретить создание экземпляров
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Парсит строковое представление криптопротокола в enum {@link HttpClient.CryptoProtocol}.
     *
     * <p>Парсинг не чувствителен к регистру. Null и пустая строка трактуются как "standard".
     * Нераспознанные значения также возвращают STANDARD_TLS для обратной совместимости.
     *
     * @param protocol строковое представление протокола (case-insensitive)
     * @return соответствующий {@link HttpClient.CryptoProtocol}, по умолчанию STANDARD_TLS
     *
     * @example
     * <pre>
     * CryptoProtocolParser.parse("standard")   → STANDARD_TLS
     * CryptoProtocolParser.parse("gost")       → CRYPTOPRO_JCSP
     * CryptoProtocolParser.parse("CryptoPro")  → CRYPTOPRO_JCSP
     * CryptoProtocolParser.parse(null)         → STANDARD_TLS
     * CryptoProtocolParser.parse("unknown")    → STANDARD_TLS
     * </pre>
     */
    public static HttpClient.CryptoProtocol parse(String protocol) {
        if (protocol == null || protocol.trim().isEmpty()) {
            return HttpClient.CryptoProtocol.STANDARD_TLS;
        }

        String normalizedProtocol = protocol.trim().toLowerCase();

        switch (normalizedProtocol) {
            case "gost":
            case "cryptopro":
            case "crypto-pro":
            case "jcsp":
                return HttpClient.CryptoProtocol.CRYPTOPRO_JCSP;

            case "standard":
            case "tls":
            case "ssl":
            default:
                return HttpClient.CryptoProtocol.STANDARD_TLS;
        }
    }

    /**
     * Парсит криптопротокол со строгой проверкой.
     *
     * <p>В отличие от {@link #parse(String)}, этот метод выбрасывает исключение
     * при нераспознанном значении вместо возврата значения по умолчанию.
     *
     * @param protocol строковое представление протокола
     * @return соответствующий {@link HttpClient.CryptoProtocol}
     * @throws IllegalArgumentException если протокол не распознан
     */
    public static HttpClient.CryptoProtocol parseStrict(String protocol) {
        if (protocol == null || protocol.trim().isEmpty()) {
            return HttpClient.CryptoProtocol.STANDARD_TLS;
        }

        String normalizedProtocol = protocol.trim().toLowerCase();

        switch (normalizedProtocol) {
            case "gost":
            case "cryptopro":
            case "crypto-pro":
            case "jcsp":
                return HttpClient.CryptoProtocol.CRYPTOPRO_JCSP;

            case "standard":
            case "tls":
            case "ssl":
                return HttpClient.CryptoProtocol.STANDARD_TLS;

            default:
                throw new IllegalArgumentException(
                    String.format("Неизвестный криптографический протокол: '%s'. " +
                        "Допустимые значения: standard, gost, cryptopro", protocol)
                );
        }
    }

    /**
     * Проверяет, является ли строка валидным криптопротоколом.
     *
     * @param protocol строковое представление протокола
     * @return true если протокол валиден
     */
    public static boolean isValidProtocol(String protocol) {
        try {
            parseStrict(protocol);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Проверяет, требует ли указанный протокол установки CryptoPro JCSP.
     *
     * @param protocol строковое представление протокола
     * @return true если это GOST/CryptoPro протокол
     */
    public static boolean requiresCryptoPro(String protocol) {
        return parse(protocol) == HttpClient.CryptoProtocol.CRYPTOPRO_JCSP;
    }
}
