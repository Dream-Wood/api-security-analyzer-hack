package active.http;

import java.util.logging.Logger;

/**
 * Фабрика для создания HTTP клиентов на основе требований криптографического протокола.
 * Эта фабрика позволяет приложению адаптироваться к различным средам безопасности,
 * выбирая соответствующую реализацию HTTP клиента.
 *
 * <p>Поддерживаемые протоколы:
 * <ul>
 *   <li>STANDARD_TLS - стандартный TLS/SSL</li>
 *   <li>CRYPTOPRO_JCSP - ГОСТ криптография через CryptoPro JCSP</li>
 *   <li>CUSTOM - пользовательская реализация</li>
 * </ul>
 */
public final class HttpClientFactory {
    private static final Logger logger = Logger.getLogger(HttpClientFactory.class.getName());

    private HttpClientFactory() {
        // Prevent instantiation
    }

    /**
     * Создать HTTP клиент на основе предоставленной конфигурации.
     *
     * @param config конфигурация HTTP клиента
     * @return экземпляр HTTP клиента
     * @throws UnsupportedOperationException если запрошенный криптографический протокол не поддерживается
     */
    public static HttpClient createClient(HttpClientConfig config) {
        HttpClient.CryptoProtocol protocol = config.getCryptoProtocol();

        logger.info("Creating HTTP client with crypto protocol: " + protocol.getDisplayName());

        return switch (protocol) {
            case STANDARD_TLS -> new StandardHttpClient(config);
            case CRYPTOPRO_JCSP -> createCryptoProClient(config);
            case CUSTOM -> throw new UnsupportedOperationException(
                "Custom crypto protocol requires explicit client implementation"
            );
        };
    }

    /**
     * Создать стандартный HTTP клиент с конфигурацией по умолчанию.
     *
     * @return стандартный HTTP клиент
     */
    public static HttpClient createDefaultClient() {
        HttpClientConfig config = HttpClientConfig.builder()
            .cryptoProtocol(HttpClient.CryptoProtocol.STANDARD_TLS)
            .build();
        return createClient(config);
    }

    /**
     * Создать CryptoPro JCSP HTTP клиент.
     * Этот метод пытается загрузить реализацию CryptoPro динамически.
     *
     * @param config конфигурация HTTP клиента
     * @return CryptoPro HTTP клиент
     * @throws UnsupportedOperationException если библиотеки CryptoPro недоступны
     */
    private static HttpClient createCryptoProClient(HttpClientConfig config) {
        try {
            // Try to load CryptoPro JCSP provider
            Class.forName("ru.CryptoPro.JCSP.JCSP");

            // Dynamically load the CryptoPro HTTP client implementation
            Class<?> clientClass = Class.forName("active.http.CryptoProHttpClient");
            return (HttpClient) clientClass
                .getConstructor(HttpClientConfig.class)
                .newInstance(config);

        } catch (ClassNotFoundException e) {
            throw new UnsupportedOperationException(
                "CryptoPro JCSP libraries not found. Please ensure ru.cryptopro:jcsp is in classpath",
                e
            );
        } catch (Exception e) {
            logger.severe("Exception creating CryptoPro HTTP client: " + e.getClass().getName());
            logger.severe("Exception message: " + e.getMessage());
            if (e.getCause() != null) {
                logger.severe("Caused by: " + e.getCause().getClass().getName() + ": " + e.getCause().getMessage());
            }
            throw new RuntimeException(
                "Failed to create CryptoPro HTTP client: " + e.getClass().getName() +
                (e.getMessage() != null ? " - " + e.getMessage() : ""),
                e
            );
        }
    }

    /**
     * Проверить, доступен ли конкретный криптографический протокол.
     *
     * @param protocol криптографический протокол для проверки
     * @return true если доступен, false в противном случае
     */
    public static boolean isProtocolAvailable(HttpClient.CryptoProtocol protocol) {
        return switch (protocol) {
            case STANDARD_TLS -> true;
            case CRYPTOPRO_JCSP -> isCryptoProAvailable();
            case CUSTOM -> false;
        };
    }

    /**
     * Проверить, доступны ли библиотеки CryptoPro JCSP.
     *
     * @return true если доступны, false в противном случае
     */
    private static boolean isCryptoProAvailable() {
        try {
            Class.forName("ru.CryptoPro.JCSP.JCSP");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }
}
