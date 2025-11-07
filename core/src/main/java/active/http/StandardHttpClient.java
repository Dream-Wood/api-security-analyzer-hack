package active.http;

import active.model.TestRequest;
import active.model.TestResponse;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Стандартная реализация HTTP клиента используя java.net.HttpURLConnection с поддержкой SSL/TLS.
 * Эта реализация не требует внешних зависимостей.
 *
 * <p>Основные возможности:
 * <ul>
 *   <li>Поддержка HTTP/HTTPS протоколов</li>
 *   <li>Поддержка нестандартных методов (PATCH через X-HTTP-Method-Override)</li>
 *   <li>Настраиваемые таймауты и SSL</li>
 *   <li>Автоматическое чтение тела ответа для ошибок</li>
 * </ul>
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

            // Set request method (with PATCH support via fallback)
            String originalMethod = request.getMethod();
            String actualMethod = setRequestMethod(connection, originalMethod);

            // Add default headers from config
            config.getDefaultHeaders().forEach(connection::setRequestProperty);

            // Add headers from request (override defaults)
            request.getHeaders().forEach(connection::setRequestProperty);

            // If method was changed to POST for PATCH support, add override header
            if (!originalMethod.equals("POST") && actualMethod.equals(originalMethod) &&
                !originalMethod.equals(connection.getRequestMethod())) {
                connection.setRequestProperty("X-HTTP-Method-Override", originalMethod);
            }

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

            // Provide detailed error message for common issues
            String errorMsg = "Request failed: " + request.getMethod() + " " + request.getFullUrl();
            if (e.getMessage() != null) {
                if (e.getMessage().contains("Illegal character")) {
                    errorMsg += " - Illegal character in URL or headers. URL may contain unencoded special characters.";
                } else if (e.getMessage().contains("MalformedURL")) {
                    errorMsg += " - Malformed URL. Check for unsubstituted path parameters or invalid characters.";
                } else {
                    errorMsg += " - " + e.getMessage();
                }
            }
            logger.log(Level.WARNING, errorMsg, e);

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

    /**
     * Установить метод запроса с поддержкой PATCH и других нестандартных методов.
     *
     * <p>HttpURLConnection не поддерживает PATCH по умолчанию. Для PATCH запросов
     * используется POST метод с заголовком X-HTTP-Method-Override как fallback.
     * Это стандартный подход, поддерживаемый многими REST API.
     *
     * @param connection HTTP соединение
     * @param method HTTP метод
     * @return фактический установленный метод (может отличаться от запрошенного для PATCH)
     * @throws IOException если не удалось установить метод
     */
    private String setRequestMethod(HttpURLConnection connection, String method) throws IOException {
        try {
            connection.setRequestMethod(method);
            return method;
        } catch (ProtocolException e) {
            // PATCH is not supported by HttpURLConnection
            // Try reflection first (works in Java 8 and with --add-opens flag)
            try {
                Field methodField;
                try {
                    methodField = HttpURLConnection.class.getDeclaredField("method");
                } catch (NoSuchFieldException ex) {
                    Class<?> parentClass = connection.getClass().getSuperclass();
                    methodField = parentClass.getDeclaredField("method");
                }
                methodField.setAccessible(true);
                methodField.set(connection, method);
                return method;
            } catch (Exception reflectionEx) {
                // Reflection failed (Java 9+ module system restriction)
                // Fallback: Use POST with X-HTTP-Method-Override header
                // This is a standard way to tunnel non-standard HTTP methods
                logger.fine("Cannot set " + method + " method directly. Using POST with X-HTTP-Method-Override header.");
                connection.setRequestMethod("POST");
                return method; // Return original method, we'll add the override header
            }
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
     * Настроить SSL контекст для принятия всех сертификатов (НЕБЕЗОПАСНО).
     * Должно использоваться только для целей тестирования.
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
