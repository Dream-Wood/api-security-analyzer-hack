package active.http;

import active.model.TestRequest;
import active.model.TestResponse;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Standard HTTP client implementation using java.net.HttpURLConnection with SSL/TLS support.
 * This implementation doesn't require external dependencies.
 */
public final class StandardHttpClient implements HttpClient {
    private static final Logger logger = Logger.getLogger(StandardHttpClient.class.getName());

    private final HttpClientConfig config;

    public StandardHttpClient(HttpClientConfig config) {
        this.config = config;

        // Configure SSL if needed
        if (!config.isVerifySsl()) {
            logger.warning("SSL verification is disabled - use only for testing!");
            configureInsecureSSL();
        }
    }

    @Override
    public TestResponse execute(TestRequest request) {
        long startTime = System.currentTimeMillis();

        try {
            URL url = new URL(request.getFullUrl());
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            // Configure connection
            configureConnection(connection, request);

            // Set request method
            connection.setRequestMethod(request.getMethod());

            // Add default headers from config
            config.getDefaultHeaders().forEach(connection::setRequestProperty);

            // Add headers from request (override defaults)
            request.getHeaders().forEach(connection::setRequestProperty);

            // Send request body if present
            if (request.getBody() != null && !request.getBody().isEmpty()) {
                connection.setDoOutput(true);
                if (request.getBodyContentType() != null) {
                    connection.setRequestProperty("Content-Type", request.getBodyContentType());
                }

                try (OutputStream os = connection.getOutputStream()) {
                    byte[] bodyBytes = request.getBody().getBytes(StandardCharsets.UTF_8);
                    os.write(bodyBytes);
                    os.flush();
                }
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
        return CryptoProtocol.STANDARD_TLS;
    }

    @Override
    public boolean supports(String url) {
        return url != null && (url.startsWith("http://") || url.startsWith("https://"));
    }

    @Override
    public void close() {
        // HttpURLConnection doesn't maintain persistent connections that need cleanup
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

    /**
     * Configure the SSL context to accept all certificates (INSECURE).
     * This should only be used for testing purposes.
     */
    private void configureInsecureSSL() {
        try {
            // Create a trust manager that accepts all certificates
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                        // Accept all
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                        // Accept all
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
            };

            // Install the trust manager
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

        } catch (Exception e) {
            throw new RuntimeException("Failed to configure insecure SSL", e);
        }
    }
}
