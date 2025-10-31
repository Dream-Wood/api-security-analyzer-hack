package active.http;

import java.util.logging.Logger;

/**
 * Factory for creating HTTP clients based on cryptographic protocol requirements.
 * This factory enables the application to adapt to different security environments
 * by selecting the appropriate HTTP client implementation.
 */
public final class HttpClientFactory {
    private static final Logger logger = Logger.getLogger(HttpClientFactory.class.getName());

    private HttpClientFactory() {
        // Prevent instantiation
    }

    /**
     * Create an HTTP client based on the provided configuration.
     *
     * @param config the HTTP client configuration
     * @return an HTTP client instance
     * @throws UnsupportedOperationException if the requested crypto protocol is not supported
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
     * Create a standard HTTP client with default configuration.
     *
     * @return a standard HTTP client
     */
    public static HttpClient createDefaultClient() {
        HttpClientConfig config = HttpClientConfig.builder()
            .cryptoProtocol(HttpClient.CryptoProtocol.STANDARD_TLS)
            .build();
        return createClient(config);
    }

    /**
     * Create a CryptoPro JCSP HTTP client.
     * This method attempts to load the CryptoPro implementation dynamically.
     *
     * @param config the HTTP client configuration
     * @return a CryptoPro HTTP client
     * @throws UnsupportedOperationException if CryptoPro libraries are not available
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
            throw new RuntimeException(
                "Failed to create CryptoPro HTTP client: " + e.getMessage(),
                e
            );
        }
    }

    /**
     * Check if a specific crypto protocol is available.
     *
     * @param protocol the crypto protocol to check
     * @return true if available, false otherwise
     */
    public static boolean isProtocolAvailable(HttpClient.CryptoProtocol protocol) {
        return switch (protocol) {
            case STANDARD_TLS -> true;
            case CRYPTOPRO_JCSP -> isCryptoProAvailable();
            case CUSTOM -> false;
        };
    }

    /**
     * Check if CryptoPro JCSP libraries are available.
     *
     * @return true if available, false otherwise
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
