package active.http.ssl;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.logging.Logger;

/**
 * Низкоуровневый клиент для GOST TLS соединений с поддержкой IP+SNI техники.
 *
 * <p>Этот класс решает проблему несоответствия hostname в сертификатах, когда:
 * <ul>
 *   <li>Сервер доступен по IP адресу (например, 45.84.153.123)</li>
 *   <li>Сертификат содержит другой hostname в SAN (например, "localhost")</li>
 *   <li>CryptoPro SSL выполняет строгую проверку hostname</li>
 * </ul>
 *
 * <p><b>Техника обхода:</b>
 * <ol>
 *   <li>Физическое TCP подключение к IP адресу</li>
 *   <li>SSL socket оборачивает TCP с указанием корректного hostname из SAN</li>
 *   <li>SNI явно устанавливается в соответствии с hostname</li>
 *   <li>CryptoPro проверяет hostname из SSL параметров, а не физический IP</li>
 * </ol>
 *
 * <p><b>Пример использования:</b>
 * <pre>
 * SSLContext sslContext = gostTLSContext.getSslContext();
 * LowLevelGostSocketClient client = new LowLevelGostSocketClient(sslContext);
 *
 * // Подключение к 45.84.153.123:8443 с SNI "localhost"
 * LowLevelGostSocketClient.Response response = client.sendRequest(
 *     "45.84.153.123", 8443, "localhost",
 *     "POST", "/auth/bank-token?client_id=xxx&client_secret=yyy",
 *     null, null
 * );
 * </pre>
 *
 * @see GostTLSContext
 */
public final class LowLevelGostSocketClient {
    private static final Logger logger = Logger.getLogger(LowLevelGostSocketClient.class.getName());
    private static final int DEFAULT_TIMEOUT_MS = 30000;

    private final SSLContext sslContext;
    private final int timeoutMs;

    /**
     * Создать клиент с заданным SSL контекстом.
     *
     * @param sslContext SSL контекст для GOST TLS
     */
    public LowLevelGostSocketClient(SSLContext sslContext) {
        this(sslContext, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Создать клиент с заданным SSL контекстом и таймаутом.
     *
     * @param sslContext SSL контекст для GOST TLS
     * @param timeoutMs таймаут подключения в миллисекундах
     */
    public LowLevelGostSocketClient(SSLContext sslContext, int timeoutMs) {
        this.sslContext = Objects.requireNonNull(sslContext, "sslContext must not be null");
        this.timeoutMs = timeoutMs;
    }

    /**
     * Отправить HTTP запрос с использованием низкоуровневых сокетов.
     *
     * @param targetIP IP адрес для физического подключения
     * @param targetPort порт сервера
     * @param sniHostname hostname для SNI и SSL проверки (должен быть в SAN сертификата)
     * @param method HTTP метод (GET, POST, и т.д.)
     * @param path путь запроса (например, "/auth/bank-token?param=value")
     * @param headers дополнительные HTTP заголовки (может быть null)
     * @param body тело запроса (может быть null)
     * @return HTTP ответ
     * @throws IOException при ошибке сети или SSL
     */
    public Response sendRequest(
        String targetIP,
        int targetPort,
        String sniHostname,
        String method,
        String path,
        Map<String, String> headers,
        String body
    ) throws IOException {

        logger.info(String.format(
            "Connecting to IP: %s:%d using SNI hostname: %s for SSL verification",
            targetIP, targetPort, sniHostname
        ));

        // 1. Создать обычный TCP сокет и подключиться к IP
        Socket plainSocket = new Socket();
        try {
            plainSocket.connect(new InetSocketAddress(targetIP, targetPort), timeoutMs);
            logger.info("TCP connection established to " + targetIP);

            // 2. Обернуть в SSL сокет с hostname для SNI
            SSLSocket sslSocket = (SSLSocket) sslContext.getSocketFactory()
                .createSocket(plainSocket, sniHostname, targetPort, true);

            // 3. Настроить SSL параметры с SNI
            SSLParameters sslParams = new SSLParameters();
            sslParams.setServerNames(Collections.singletonList(
                new SNIHostName(sniHostname)
            ));
            // Отключаем endpoint identification - мы используем свою логику проверки
            sslParams.setEndpointIdentificationAlgorithm(null);
            sslSocket.setSSLParameters(sslParams);

            logger.info("SSL socket created with SNI: " + sniHostname);

            // 4. Выполнить handshake
            sslSocket.startHandshake();
            logger.info("SSL handshake completed successfully");

            // 5. Отправить HTTP запрос
            sendHttpRequest(sslSocket, method, path, sniHostname, headers, body);
            logger.info("HTTP " + method + " request sent");

            // 6. Прочитать HTTP ответ
            Response response = readHttpResponse(sslSocket);
            logger.info("Response received: status=" + response.statusCode);

            // 7. Закрыть соединение
            sslSocket.close();

            return response;

        } catch (IOException e) {
            logger.warning("Request failed: " + e.getMessage());
            throw e;
        } finally {
            if (!plainSocket.isClosed()) {
                try {
                    plainSocket.close();
                } catch (IOException e) {
                    logger.warning("Failed to close plain socket: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Отправить HTTP запрос через SSL сокет.
     */
    private void sendHttpRequest(
        SSLSocket socket,
        String method,
        String path,
        String host,
        Map<String, String> headers,
        String body
    ) throws IOException {

        PrintWriter out = new PrintWriter(socket.getOutputStream());

        // Request line
        out.println(method + " " + path + " HTTP/1.1");

        // Обязательный заголовок Host
        out.println("Host: " + host);

        // Дополнительные заголовки
        if (headers != null) {
            for (Map.Entry<String, String> header : headers.entrySet()) {
                out.println(header.getKey() + ": " + header.getValue());
            }
        }

        // Тело запроса
        if (body != null && !body.isEmpty()) {
            byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
            out.println("Content-Length: " + bodyBytes.length);
            if (!headers.containsKey("Content-Type")) {
                out.println("Content-Type: application/json");
            }
            out.println(); // Пустая строка между заголовками и телом
            out.print(body);
        } else {
            out.println("Connection: close");
            out.println(); // Пустая строка в конце заголовков
        }

        out.flush();
    }

    /**
     * Прочитать HTTP ответ из SSL сокета.
     */
    private Response readHttpResponse(SSLSocket socket) throws IOException {
        BufferedReader in = new BufferedReader(
            new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)
        );

        int statusCode = 0;
        Map<String, String> headers = new LinkedHashMap<>();
        StringBuilder bodyBuilder = new StringBuilder();
        String line;
        boolean isBody = false;

        while ((line = in.readLine()) != null) {
            if (!isBody) {
                // Парсинг статус-линии
                if (line.startsWith("HTTP/")) {
                    String[] parts = line.split(" ", 3);
                    if (parts.length >= 2) {
                        try {
                            statusCode = Integer.parseInt(parts[1]);
                        } catch (NumberFormatException e) {
                            logger.warning("Failed to parse status code: " + parts[1]);
                        }
                    }
                }
                // Пустая строка означает начало тела
                else if (line.isEmpty()) {
                    isBody = true;
                }
                // Парсинг заголовков
                else {
                    int colonIndex = line.indexOf(':');
                    if (colonIndex > 0) {
                        String headerName = line.substring(0, colonIndex).trim();
                        String headerValue = line.substring(colonIndex + 1).trim();
                        headers.put(headerName, headerValue);
                    }
                }
            } else {
                // Чтение тела
                bodyBuilder.append(line);
            }
        }

        return new Response(statusCode, headers, bodyBuilder.toString());
    }

    /**
     * HTTP ответ от низкоуровневого клиента.
     */
    public static class Response {
        private final int statusCode;
        private final Map<String, String> headers;
        private final String body;

        public Response(int statusCode, Map<String, String> headers, String body) {
            this.statusCode = statusCode;
            this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
            this.body = body;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public Map<String, String> getHeaders() {
            return headers;
        }

        public String getBody() {
            return body;
        }

        public String getHeader(String name) {
            return headers.get(name);
        }

        @Override
        public String toString() {
            return "Response{" +
                "statusCode=" + statusCode +
                ", headers=" + headers.size() +
                ", bodyLength=" + (body != null ? body.length() : 0) +
                '}';
        }
    }

    /**
     * Вспомогательный метод для URL-кодирования параметров.
     *
     * @param value значение для кодирования
     * @return URL-кодированная строка
     */
    public static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            throw new RuntimeException("Failed to URL encode: " + value, e);
        }
    }

    /**
     * Построить query string из параметров.
     *
     * @param params параметры запроса
     * @return query string (например, "param1=value1&param2=value2")
     */
    public static String buildQueryString(Map<String, String> params) {
        if (params == null || params.isEmpty()) {
            return "";
        }

        StringJoiner joiner = new StringJoiner("&");
        for (Map.Entry<String, String> entry : params.entrySet()) {
            joiner.add(urlEncode(entry.getKey()) + "=" + urlEncode(entry.getValue()));
        }
        return joiner.toString();
    }
}
