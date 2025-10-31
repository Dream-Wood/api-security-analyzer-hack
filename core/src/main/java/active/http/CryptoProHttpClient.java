package active.http;

import active.model.TestRequest;
import active.model.TestResponse;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * HTTP client implementation with CryptoPro JCSP support for GOST cryptography.
 * This implementation uses HttpURLConnection with CryptoPro security provider.
 *
 * <p>Supports GOST TLS protocols including GostTLS and GostTLSv1.3.
 *
 * <p><b>Required CryptoPro libraries:</b>
 * <ul>
 *   <li>JCP (Java Crypto Provider) - ru.CryptoPro.JCP.JCP</li>
 *   <li>SSL Provider - ru.CryptoPro.ssl.Provider</li>
 *   <li>Crypto Provider - ru.CryptoPro.Crypto.CryptoProvider</li>
 *   <li>RevCheck (optional) - ru.CryptoPro.reprov.RevCheck</li>
 * </ul>
 *
 * <p><b>Configuration via HttpClientConfig:</b>
 * <pre>
 * config.addCustomSetting("gostProtocol", "GostTLSv1.3"); // or "GostTLS"
 * config.addCustomSetting("keyStoreType", "HDImageStore");
 * config.addCustomSetting("keyStorePath", "NONE"); // auto-discovery
 * </pre>
 *
 * @see <a href="https://habr.com/ru/companies/alfastrah/articles/823974/">GOST TLS Configuration Guide</a>
 * @see <a href="https://habr.com/ru/articles/862188/">CryptoPro in JMeter</a>
 */
public final class CryptoProHttpClient implements HttpClient {
    private static final Logger logger = Logger.getLogger(CryptoProHttpClient.class.getName());

    // CryptoPro provider class names
    private static final String JCP_PROVIDER = "ru.CryptoPro.JCP.JCP";
    private static final String SSL_PROVIDER = "ru.CryptoPro.ssl.Provider";
    private static final String CRYPTO_PROVIDER = "ru.CryptoPro.Crypto.CryptoProvider";
    private static final String REVCHECK_PROVIDER = "ru.CryptoPro.reprov.RevCheck";

    // Default GOST protocol
    private static final String DEFAULT_GOST_PROTOCOL = "GostTLS";

    private final HttpClientConfig config;
    private final SSLContext sslContext;

    public CryptoProHttpClient(HttpClientConfig config) {
        this.config = config;
        initializeCryptoProProviders();
        this.sslContext = createGostSSLContext();

        logger.info("CryptoProHttpClient initialized with GOST TLS support");
    }

    @Override
    public TestResponse execute(TestRequest request) {
        long startTime = System.currentTimeMillis();

        try {
            URL url = new URL(request.getFullUrl());
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            // Configure connection
            configureConnection(connection, request);

            // Configure CryptoPro SSL if HTTPS
            if (request.getFullUrl().startsWith("https://")) {
                configureHttpsConnection((HttpsURLConnection) connection);
            }

            // Set request method
            connection.setRequestMethod(request.getMethod());

            // Add headers
            config.getDefaultHeaders().forEach(connection::setRequestProperty);
            request.getHeaders().forEach(connection::setRequestProperty);

            // Send request body if present
            if (request.getBody() != null) {
                connection.setDoOutput(true);
                if (request.getBodyContentType() != null) {
                    connection.setRequestProperty("Content-Type", request.getBodyContentType());
                }
                byte[] bodyBytes = request.getBody().getBytes(StandardCharsets.UTF_8);
                connection.getOutputStream().write(bodyBytes);
            }

            // Get response
            int statusCode = connection.getResponseCode();
            long responseTime = System.currentTimeMillis() - startTime;

            // Read response body
            String body = readResponseBody(connection, statusCode);

            // Extract headers
            Map<String, List<String>> headers = new LinkedHashMap<>(connection.getHeaderFields());
            headers.remove(null); // Remove status line

            connection.disconnect();

            return TestResponse.builder()
                .statusCode(statusCode)
                .headers(headers)
                .body(body)
                .responseTimeMs(responseTime)
                .build();

        } catch (IOException e) {
            long responseTime = System.currentTimeMillis() - startTime;
            logger.log(Level.WARNING, "Request failed: " + request, e);

            return TestResponse.builder()
                .statusCode(0)
                .responseTimeMs(responseTime)
                .error(e)
                .build();
        }
    }

    @Override
    public CryptoProtocol getCryptoProtocol() {
        return CryptoProtocol.CRYPTOPRO_JCSP;
    }

    @Override
    public boolean supports(String url) {
        return url != null && (url.startsWith("http://") || url.startsWith("https://"));
    }

    @Override
    public void close() {
        // HttpURLConnection doesn't maintain persistent connections in the same way
        // No cleanup needed
    }

    /**
     * Initialize all required CryptoPro security providers.
     * Providers are registered in specific order for proper GOST TLS operation.
     */
    private void initializeCryptoProProviders() {
        String[] providers = {
            JCP_PROVIDER,           // Main cryptographic provider
            SSL_PROVIDER,           // GOST SSL/TLS provider
            CRYPTO_PROVIDER,        // Additional crypto operations
            REVCHECK_PROVIDER       // Certificate revocation checking (optional)
        };

        for (String providerClass : providers) {
            try {
                registerProvider(providerClass);
            } catch (ClassNotFoundException e) {
                // RevCheck is optional, others are required
                if (!providerClass.equals(REVCHECK_PROVIDER)) {
                    throw new RuntimeException(
                        "Required CryptoPro provider not found: " + providerClass + ". " +
                        "Ensure CryptoPro JCP libraries are in classpath.",
                        e
                    );
                } else {
                    logger.fine("Optional provider not available: " + providerClass);
                }
            } catch (Exception e) {
                throw new RuntimeException(
                    "Failed to initialize CryptoPro provider: " + providerClass,
                    e
                );
            }
        }
    }

    /**
     * Register a security provider by class name.
     */
    private void registerProvider(String className) throws Exception {
        Class<?> providerClass = Class.forName(className);
        Provider provider = (Provider) providerClass.getDeclaredConstructor().newInstance();

        // Check if already registered
        if (Security.getProvider(provider.getName()) == null) {
            Security.addProvider(provider);
            logger.info("Registered CryptoPro provider: " + provider.getName() +
                       " (" + className + ")");
        } else {
            logger.fine("Provider already registered: " + provider.getName());
        }
    }

    /**
     * Create and configure GOST SSL context.
     * Uses GostTLS or GostTLSv1.3 protocol with CryptoPro provider.
     */
    private SSLContext createGostSSLContext() {
        try {
            // Get protocol from config or use default
            String protocol = config.getCustomSetting("gostProtocol")
                .map(Object::toString)
                .orElse(DEFAULT_GOST_PROTOCOL);

            logger.info("Creating GOST SSL context with protocol: " + protocol);

            // Create SSL context with GOST protocol
            SSLContext context = SSLContext.getInstance(protocol);

            // Initialize based on SSL verification setting
            if (config.isVerifySsl()) {
                // For production: use proper KeyManager and TrustManager
                KeyManager[] keyManagers = createKeyManagers();
                TrustManager[] trustManagers = createTrustManagers();
                context.init(keyManagers, trustManagers, new java.security.SecureRandom());

                logger.info("SSL context initialized with certificate verification");
            } else {
                // For testing: trust all certificates
                logger.warning("SSL verification disabled - USING TRUST-ALL MODE (testing only!)");
                TrustManager[] trustAll = createTrustAllManager();
                context.init(null, trustAll, new java.security.SecureRandom());
            }

            return context;

        } catch (Exception e) {
            throw new RuntimeException(
                "Failed to create GOST SSL context. " +
                "Ensure CryptoPro providers are properly configured and licensed.",
                e
            );
        }
    }

    /**
     * Create KeyManagers for client certificate authentication.
     * Uses HDImageStore for CryptoPro key containers.
     */
    private KeyManager[] createKeyManagers() throws Exception {
        try {
            String keyStoreType = config.getCustomSetting("keyStoreType")
                .map(Object::toString)
                .orElse("HDImageStore");

            String keyStorePath = config.getCustomSetting("keyStorePath")
                .map(Object::toString)
                .orElse("NONE"); // NONE = auto-discovery of key containers

            logger.fine("Loading key store: type=" + keyStoreType + ", path=" + keyStorePath);

            // Load key store
            java.security.KeyStore keyStore = java.security.KeyStore.getInstance(keyStoreType);

            if ("NONE".equals(keyStorePath)) {
                // Auto-discovery mode - CryptoPro will find available containers
                keyStore.load(null, null);
            } else {
                // Load from specific path (if needed)
                char[] password = config.getCustomSetting("keyStorePassword")
                    .map(Object::toString)
                    .map(String::toCharArray)
                    .orElse(null);

                try (var is = new java.io.FileInputStream(keyStorePath)) {
                    keyStore.load(is, password);
                }
            }

            // Initialize KeyManagerFactory
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm()
            );
            kmf.init(keyStore, null);

            return kmf.getKeyManagers();

        } catch (Exception e) {
            logger.warning("Failed to create KeyManagers, using null: " + e.getMessage());
            return null; // Null is acceptable if client certificates not needed
        }
    }

    /**
     * Create TrustManagers for server certificate verification.
     */
    private TrustManager[] createTrustManagers() throws Exception {
        try {
            // Use system trust store (cacerts) with GOST certificates
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
            );
            tmf.init((java.security.KeyStore) null);

            return tmf.getTrustManagers();

        } catch (Exception e) {
            logger.warning("Failed to create TrustManagers: " + e.getMessage());
            throw e;
        }
    }

    private void configureConnection(HttpURLConnection connection, TestRequest request) {
        connection.setConnectTimeout((int) config.getConnectTimeout().toMillis());
        connection.setReadTimeout((int) config.getReadTimeout().toMillis());
        connection.setInstanceFollowRedirects(config.isFollowRedirects());

        // Use custom timeout from request if specified
        if (request.getTimeoutMs() > 0) {
            connection.setConnectTimeout(request.getTimeoutMs());
            connection.setReadTimeout(request.getTimeoutMs());
        }
    }

    private void configureHttpsConnection(HttpsURLConnection connection) {
        // Apply pre-configured GOST SSL context
        connection.setSSLSocketFactory(sslContext.getSocketFactory());

        // Disable hostname verification if SSL verification is disabled
        if (!config.isVerifySsl()) {
            connection.setHostnameVerifier((hostname, session) -> true);
        }
    }

    private TrustManager[] createTrustAllManager() {
        return new TrustManager[]{
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                }

                @Override
                public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                }

                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return new java.security.cert.X509Certificate[0];
                }
            }
        };
    }

    private String readResponseBody(HttpURLConnection connection, int statusCode) throws IOException {
        try (var inputStream = statusCode >= 400
            ? connection.getErrorStream()
            : connection.getInputStream()) {

            if (inputStream == null) {
                return null;
            }

            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
