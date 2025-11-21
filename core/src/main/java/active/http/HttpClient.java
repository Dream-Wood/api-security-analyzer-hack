package active.http;

import active.model.TestRequest;
import active.model.TestResponse;

/**
 * Интерфейс для реализаций HTTP-клиентов, поддерживающих различные криптографические протоколы.
 * Реализации могут поддерживать стандартный SSL/TLS, CryptoPro JCSP или другие пользовательские протоколы.
 *
 * <p>Основные реализации:
 * <ul>
 *   <li>{@link StandardHttpClient} - стандартный TLS/SSL клиент</li>
 *   <li>{@link CryptoProHttpClient} - клиент с поддержкой ГОСТ криптографии</li>
 * </ul>
 */
public interface HttpClient extends AutoCloseable {

    /**
     * Выполняет HTTP-запрос и возвращает ответ.
     *
     * @param request тестовый запрос для выполнения
     * @return тестовый ответ
     */
    TestResponse execute(TestRequest request);

    /**
     * Возвращает тип криптографического протокола, поддерживаемого этим клиентом.
     *
     * @return тип криптографического протокола
     */
    CryptoProtocol getCryptoProtocol();

    /**
     * Проверяет, поддерживает ли этот клиент указанную схему URL.
     *
     * @param url URL для проверки
     * @return true, если поддерживается, иначе false
     */
    boolean supports(String url);

    /**
     * Закрывает клиент и освобождает удерживаемые ресурсы.
     */
    void close();

    /**
     * Поддерживаемые криптографические протоколы.
     */
    enum CryptoProtocol {
        /**
         * Стандартный SSL/TLS (например, TLS 1.2, TLS 1.3)
         */
        STANDARD_TLS("Standard TLS"),

        /**
         * Российский CryptoPro JCSP (криптография ГОСТ)
         */
        CRYPTOPRO_JCSP("CryptoPro JCSP"),

        /**
         * Пользовательский криптографический протокол
         */
        CUSTOM("Custom");

        private final String displayName;

        CryptoProtocol(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }
}
