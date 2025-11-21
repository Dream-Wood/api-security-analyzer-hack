package active.http;

import active.http.ssl.CryptoProProvider;
import active.http.ssl.GostTLSContext;
import active.http.ssl.LowLevelGostSocketClient;
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
 * Реализация HTTP клиента с поддержкой CryptoPro JCSP для криптографии ГОСТ.
 *
 * <p>Эта реализация использует HttpURLConnection с пользовательским GOST TLS контекстом,
 * созданным в соответствии с официальным шаблоном CryptoPro.
 *
 * <p><b>Возможности:</b>
 * <ul>
 *   <li>Поддержка протокола GOST TLSv1.3</li>
 *   <li>Аутентификация клиента через PFX сертификат</li>
 *   <li>Проверка серверных сертификатов через cacerts</li>
 *   <li>Проверка отзыва сертификатов</li>
 * </ul>
 *
 * <p><b>Конфигурация через HttpClientConfig:</b>
 * <pre>
 * HttpClientConfig config = HttpClientConfig.builder()
 *     .cryptoProtocol(HttpClient.CryptoProtocol.CRYPTOPRO_JCSP)
 *     .verifySsl(true)
 *     .addCustomSetting("pfxPath", "certs/cert.pfx")
 *     .addCustomSetting("pfxPassword", "password")
 *     .addCustomSetting("pfxResource", "true") // если PFX в ресурсах
 *     .addCustomSetting("enableRevocationCheck", "true") // по умолчанию: true (требует доступ к CDP)
 *     // Для обхода hostname verification через IP+SNI:
 *     .addCustomSetting("useLowLevelSocket", "true")
 *     .addCustomSetting("targetIP", "45.84.153.123")
 *     .addCustomSetting("sniHostname", "localhost")
 *     .build();
 * </pre>
 *
 * <p><b>Проверка отзыва сертификатов:</b>
 * По умолчанию проверка отзыва сертификатов ВКЛЮЧЕНА и требует сетевого доступа к:
 * <ul>
 *   <li>http://cdp.cryptopro.ru/ra/cdp/*</li>
 *   <li>http://vpnca.cryptopro.ru/cdp/*</li>
 * </ul>
 * Без доступа к CDP, TLS handshake завершится ошибкой проверки сертификата.
 * Для тестовых окружений отключите через: .addCustomSetting("enableRevocationCheck", "false")
 *
 * @see GostTLSContext
 * @see <a href="https://habr.com/ru/companies/alfastrah/articles/823974/">Руководство по конфигурации GOST TLS</a>
 */
public final class CryptoProHttpClient implements HttpClient {
    private static final Logger logger = Logger.getLogger(CryptoProHttpClient.class.getName());

    private final HttpClientConfig config;
    private final GostTLSContext tlsContext;

    public CryptoProHttpClient(HttpClientConfig config) {
        this.config = config;

        try {
            logger.info("Initializing CryptoProHttpClient...");

            // Initialize CryptoPro providers
            if (!CryptoProProvider.isAvailable()) {
                throw new RuntimeException(
                    "CryptoPro JCSP libraries not found. " +
                    "Please ensure ru.cryptopro:jcp and related libraries are in classpath."
                );
            }

            CryptoProProvider.initialize();

            // Create GOST TLS context
            logger.info("Creating GOST TLS context...");
            this.tlsContext = createGostTLSContext(config);

            logger.info("CryptoProHttpClient initialized with GOST TLS support");
        } catch (Exception e) {
            logger.severe("Failed to initialize CryptoProHttpClient: " + e.getClass().getName() + ": " + e.getMessage());
            throw e;
        }
    }

    @Override
    public TestResponse execute(TestRequest request) {
        long startTime = System.currentTimeMillis();

        // Проверить, нужно ли использовать низкоуровневые сокеты
        boolean useLowLevelSocket = config.getCustomSetting("useLowLevelSocket")
            .map(Object::toString)
            .map(Boolean::parseBoolean)
            .orElse(false);

        if (useLowLevelSocket && request.getFullUrl().startsWith("https://")) {
            return executeLowLevelSocket(request, startTime);
        }

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
     * Создать GOST TLS контекст из HttpClientConfig.
     * Конфигурирует PFX сертификат, проверку SSL и отзыв сертификатов.
     *
     * @param config конфигурация HTTP клиента
     * @return настроенный GOST TLS контекст
     * @throws RuntimeException если не удалось создать контекст
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

            // Configure certificate revocation checking
            boolean enableRevocationCheck = config.getCustomSetting("enableRevocationCheck")
                .map(Object::toString)
                .map(Boolean::parseBoolean)
                .orElse(true); // Enabled by default for security
            builder.enableRevocationCheck(enableRevocationCheck);

            logger.info("Building GostTLSContext...");
            GostTLSContext context = builder.build();
            logger.info("GostTLSContext built successfully");
            return context;

        } catch (Exception e) {
            logger.severe("Failed to create GOST TLS context: " + e.getClass().getName() + ": " + e.getMessage());
            if (e.getCause() != null) {
                logger.severe("Caused by: " + e.getCause().getClass().getName() + ": " + e.getCause().getMessage());
            }
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

    /**
     * Выполнить запрос используя низкоуровневые сокеты для обхода hostname verification.
     * <p>
     * Этот метод используется когда:
     * <ul>
     *   <li>Сервер доступен по IP адресу</li>
     *   <li>Сертификат содержит другой hostname в SAN</li>
     *   <li>CryptoPro SSL выполняет строгую проверку hostname</li>
     * </ul>
     *
     * @param request HTTP запрос
     * @param startTime время начала запроса
     * @return HTTP ответ
     */
    private TestResponse executeLowLevelSocket(TestRequest request, long startTime) {
        try {
            // Получить настройки IP+SNI
            String targetIP = config.getCustomSetting("targetIP")
                .map(Object::toString)
                .orElseThrow(() -> new IllegalArgumentException(
                    "targetIP must be specified when useLowLevelSocket=true"
                ));

            String sniHostname = config.getCustomSetting("sniHostname")
                .map(Object::toString)
                .orElseThrow(() -> new IllegalArgumentException(
                    "sniHostname must be specified when useLowLevelSocket=true"
                ));

            // Извлечь порт и путь из URL
            URL url = new URL(request.getFullUrl());
            int port = url.getPort() != -1 ? url.getPort() : url.getDefaultPort();
            String path = url.getPath();
            if (url.getQuery() != null) {
                path += "?" + url.getQuery();
            }

            logger.info(String.format(
                "Using low-level socket: IP=%s, Port=%d, SNI=%s, Path=%s",
                targetIP, port, sniHostname, path
            ));

            // Создать клиент низкоуровневых сокетов
            LowLevelGostSocketClient socketClient = new LowLevelGostSocketClient(
                tlsContext.getSslContext(),
                request.getTimeoutMs() > 0 ? request.getTimeoutMs() : (int) config.getConnectTimeout().toMillis()
            );

            // Объединить заголовки из конфигурации и запроса
            Map<String, String> allHeaders = new LinkedHashMap<>();
            config.getDefaultHeaders().forEach(allHeaders::put);
            request.getHeaders().forEach(allHeaders::put);

            // Отправить запрос
            LowLevelGostSocketClient.Response response = socketClient.sendRequest(
                targetIP,
                port,
                sniHostname,
                request.getMethod(),
                path,
                allHeaders,
                request.getBody()
            );

            long responseTime = System.currentTimeMillis() - startTime;

            // Преобразовать ответ в TestResponse
            Map<String, List<String>> headers = new LinkedHashMap<>();
            response.getHeaders().forEach((key, value) ->
                headers.put(key, Collections.singletonList(value))
            );

            return TestResponse.builder()
                .statusCode(response.getStatusCode())
                .headers(headers)
                .body(response.getBody())
                .responseTimeMs(responseTime)
                .build();

        } catch (Exception e) {
            long responseTime = System.currentTimeMillis() - startTime;
            logger.log(Level.WARNING, "Low-level socket request failed: " + request, e);

            return TestResponse.builder()
                .statusCode(0)
                .responseTimeMs(responseTime)
                .error(e)
                .build();
        }
    }
}
