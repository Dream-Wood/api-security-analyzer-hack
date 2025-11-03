package active.http;

import active.http.ssl.CryptoProProvider;
import active.http.ssl.GostTLSContext;
import active.model.TestRequest;
import active.model.TestResponse;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * HTTP client implementation with CryptoPro JCSP support for GOST cryptography.
 *
 * <p>This implementation uses HttpURLConnection with a custom GOST TLS context
 * created according to the official CryptoPro pattern.
 *
 * <p><b>Features:</b>
 * <ul>
 *   <li>GOST TLSv1.3 protocol support</li>
 *   <li>Client certificate authentication via PFX</li>
 *   <li>Server certificate verification via cacerts</li>
 *   <li>Certificate revocation checking</li>
 * </ul>
 *
 * <p><b>Configuration via HttpClientConfig:</b>
 * <pre>
 * HttpClientConfig config = HttpClientConfig.builder()
 *     .cryptoProtocol(HttpClient.CryptoProtocol.CRYPTOPRO_JCSP)
 *     .verifySsl(true)
 *     .addCustomSetting("pfxPath", "certs/cert.pfx")
 *     .addCustomSetting("pfxPassword", "password")
 *     .addCustomSetting("pfxResource", "true") // if PFX is in resources
 *     .build();
 * </pre>
 *
 * @see GostTLSContext
 * @see <a href="https://habr.com/ru/companies/alfastrah/articles/823974/">GOST TLS Configuration Guide</a>
 */
public final class CryptoProHttpClient implements HttpClient {
    private static final Logger logger = Logger.getLogger(CryptoProHttpClient.class.getName());

    private final HttpClientConfig config;
    private final GostTLSContext tlsContext;

    public CryptoProHttpClient(HttpClientConfig config) {
        this.config = config;

        // Initialize CryptoPro providers
        if (!CryptoProProvider.isAvailable()) {
            throw new RuntimeException(
                "CryptoPro JCSP libraries not found. " +
                "Please ensure ru.cryptopro:jcp and related libraries are in classpath."
            );
        }

        CryptoProProvider.initialize();

        // Create GOST TLS context
        this.tlsContext = createGostTLSContext(config);

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

            // Configure GOST SSL if HTTPS
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
        if (tlsContext != null) {
            tlsContext.close();
        }
    }

    /**
     * Create GOST TLS context from HttpClientConfig.
     */
    private GostTLSContext createGostTLSContext(HttpClientConfig config) {
        try {
            GostTLSContext.Builder builder = GostTLSContext.builder();

            // Get PFX configuration
            Optional<Object> pfxPath = config.getCustomSetting("pfxPath");
            Optional<Object> pfxPassword = config.getCustomSetting("pfxPassword");
            boolean isResource = config.getCustomSetting("pfxResource")
                .map(Object::toString)
                .map(Boolean::parseBoolean)
                .orElse(false);

            // Configure PFX certificate if provided
            if (pfxPath.isPresent()) {
                String path = pfxPath.get().toString();
                String password = pfxPassword.map(Object::toString).orElse("");

                if (isResource) {
                    builder.pfxResource(path, password);
                    logger.info("Configured PFX certificate from resource: " + path);
                } else {
                    builder.pfxCertificate(path, password);
                    logger.info("Configured PFX certificate from file: " + path);
                }
            } else {
                logger.info("No PFX certificate configured, using server authentication only");
            }

            // Configure SSL verification
            boolean verifySsl = config.isVerifySsl();
            if (!verifySsl) {
                logger.warning("SSL verification disabled (testing mode)");
            }
            builder.disableVerification(!verifySsl);

            return builder.build();

        } catch (Exception e) {
            throw new RuntimeException(
                "Failed to create GOST TLS context. " +
                "Ensure CryptoPro providers are properly configured and licensed.",
                e
            );
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
        // Apply GOST SSL context
        connection.setSSLSocketFactory(tlsContext.getSocketFactory());

        // Disable hostname verification if SSL verification is disabled
        if (!config.isVerifySsl()) {
            connection.setHostnameVerifier((hostname, session) -> true);
        }
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
