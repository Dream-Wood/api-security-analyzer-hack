package active.http;

import active.model.TestRequest;
import active.model.TestResponse;

/**
 * Interface for HTTP client implementations supporting different cryptographic protocols.
 * Implementations may support standard SSL/TLS, CryptoPro JCSP, or other custom protocols.
 */
public interface HttpClient {

    /**
     * Execute an HTTP request and return the response.
     *
     * @param request the test request to execute
     * @return the test response
     */
    TestResponse execute(TestRequest request);

    /**
     * Get the cryptographic protocol type supported by this client.
     *
     * @return the crypto protocol type
     */
    CryptoProtocol getCryptoProtocol();

    /**
     * Check if this client supports the given URL scheme.
     *
     * @param url the URL to check
     * @return true if supported, false otherwise
     */
    boolean supports(String url);

    /**
     * Close and release resources held by this client.
     */
    void close();

    /**
     * Supported cryptographic protocols.
     */
    enum CryptoProtocol {
        /**
         * Standard SSL/TLS (e.g., TLS 1.2, TLS 1.3)
         */
        STANDARD_TLS("Standard TLS"),

        /**
         * Russian CryptoPro JCSP (GOST cryptography)
         */
        CRYPTOPRO_JCSP("CryptoPro JCSP"),

        /**
         * Custom cryptographic protocol
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
