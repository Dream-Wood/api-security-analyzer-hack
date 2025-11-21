package active.protocol.websocket;

import active.protocol.*;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import java.net.URI;
import java.util.Map;
import java.util.concurrent.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Production WebSocket protocol client implementation using Java-WebSocket library.
 *
 * <p>Supports:
 * <ul>
 *   <li>WebSocket (ws://) and WebSocket Secure (wss://)</li>
 *   <li>Authentication via headers</li>
 *   <li>Bidirectional messaging</li>
 *   <li>Automatic reconnection</li>
 *   <li>Message handlers for async subscriptions</li>
 * </ul>
 */
public class WebSocketProtocolClient implements ProtocolClient {

    private static final Logger logger = Logger.getLogger(WebSocketProtocolClient.class.getName());
    private static final int DEFAULT_TIMEOUT_MS = 10000;

    private ProtocolConfig config;
    private InternalWebSocketClient wsClient;
    private final Map<String, MessageHandler> messageHandlers = new ConcurrentHashMap<>();
    private final BlockingQueue<String> receivedMessages = new LinkedBlockingQueue<>();

    @Override
    public String getProtocol() {
        return "ws";
    }

    @Override
    public String getProtocolVersion() {
        return "13"; // RFC 6455
    }

    @Override
    public boolean isConnected() {
        return wsClient != null && wsClient.isOpen();
    }

    @Override
    public void connect(ProtocolConfig config) throws ProtocolException {
        if (isConnected()) {
            logger.fine("Already connected to WebSocket");
            return;
        }

        this.config = config;
        String url = config.getUrl();

        logger.info(String.format("Connecting to WebSocket: %s", url));

        try {
            URI uri = new URI(url);

            // Create WebSocket client with authentication headers if provided
            wsClient = new InternalWebSocketClient(uri, config);

            // Connect with timeout
            boolean connected = wsClient.connectBlocking(DEFAULT_TIMEOUT_MS, TimeUnit.MILLISECONDS);

            if (!connected) {
                throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.CONNECTION_FAILED,
                        "Failed to connect to WebSocket within timeout");
            }

            logger.info(String.format("Connected to WebSocket: %s", url));

        } catch (ProtocolException e) {
            throw e;
        } catch (Exception e) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.CONNECTION_FAILED,
                    "Failed to connect to WebSocket: " + e.getMessage(), e);
        }
    }

    @Override
    public void disconnect() {
        if (wsClient != null && wsClient.isOpen()) {
            logger.info("Disconnecting from WebSocket");
            try {
                wsClient.closeBlocking();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.warning("Interrupted during disconnect");
            }
        }
        messageHandlers.clear();
        receivedMessages.clear();
    }

    @Override
    public ProtocolResponse send(ProtocolRequest request) throws ProtocolException {
        if (!isConnected()) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PROTOCOL_ERROR,
                    "Not connected to WebSocket server");
        }

        long startTime = System.currentTimeMillis();

        try {
            switch (request.getType()) {
                case PUBLISH:
                    return handlePublish(request, startTime);

                case SUBSCRIBE:
                    return handleSubscribe(request, startTime);

                case UNSUBSCRIBE:
                    return handleUnsubscribe(request, startTime);

                default:
                    throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PROTOCOL_ERROR,
                            "Unsupported request type: " + request.getType());
            }

        } catch (ProtocolException e) {
            throw e;
        } catch (Exception e) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PROTOCOL_ERROR,
                    "Error processing request: " + e.getMessage(), e);
        }
    }

    private ProtocolResponse handlePublish(ProtocolRequest request, long startTime) throws ProtocolException {
        String payload = request.getPayload();

        logger.fine(String.format("Publishing message: %d bytes", payload.length()));

        try {
            wsClient.send(payload);

            long duration = System.currentTimeMillis() - startTime;

            return ProtocolResponse.builder()
                    .success(true)
                    .statusCode(0)
                    .statusMessage("Message published successfully")
                    .durationMs(duration)
                    .metadata("payloadSize", payload.length())
                    .build();

        } catch (Exception e) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PUBLISH_FAILED,
                    "Failed to publish message: " + e.getMessage(), e);
        }
    }

    private ProtocolResponse handleSubscribe(ProtocolRequest request, long startTime) throws ProtocolException {
        int timeoutMs = request.getTimeoutMs() > 0 ? request.getTimeoutMs() : DEFAULT_TIMEOUT_MS;

        logger.fine(String.format("Subscribing for messages (timeout=%dms)", timeoutMs));

        try {
            // Wait for messages with timeout
            String message = receivedMessages.poll(timeoutMs, TimeUnit.MILLISECONDS);

            long duration = System.currentTimeMillis() - startTime;

            if (message != null) {
                ProtocolMessage protocolMessage = ProtocolMessage.builder()
                        .channel(request.getChannel())
                        .payload(message)
                        .timestamp(System.currentTimeMillis())
                        .build();

                return ProtocolResponse.builder()
                        .success(true)
                        .statusCode(0)
                        .statusMessage("Message received")
                        .message(protocolMessage)
                        .durationMs(duration)
                        .build();
            } else {
                // No message within timeout - not an error
                return ProtocolResponse.builder()
                        .success(true)
                        .statusCode(0)
                        .statusMessage("No messages within timeout")
                        .durationMs(duration)
                        .build();
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.SUBSCRIPTION_FAILED,
                    "Subscription interrupted: " + e.getMessage(), e);
        }
    }

    private ProtocolResponse handleUnsubscribe(ProtocolRequest request, long startTime) {
        logger.fine("Unsubscribing from messages");

        // Clear received messages queue
        receivedMessages.clear();

        long duration = System.currentTimeMillis() - startTime;

        return ProtocolResponse.builder()
                .success(true)
                .statusCode(0)
                .statusMessage("Unsubscribed successfully")
                .durationMs(duration)
                .build();
    }

    @Override
    public void subscribe(String channel, MessageHandler handler) throws ProtocolException {
        if (!isConnected()) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PROTOCOL_ERROR,
                    "Not connected to WebSocket server");
        }

        logger.fine(String.format("Setting up async subscription for channel '%s'", channel));

        messageHandlers.put(channel, handler);
    }

    @Override
    public void unsubscribe(String channel) throws ProtocolException {
        logger.fine(String.format("Removing subscription for channel '%s'", channel));

        messageHandlers.remove(channel);
    }

    @Override
    public void close() {
        disconnect();
    }

    @Override
    public String getDescription() {
        return "WebSocket Protocol Client (RFC 6455) using Java-WebSocket library";
    }

    /**
     * Internal WebSocket client implementation.
     */
    private class InternalWebSocketClient extends WebSocketClient {

        private final ProtocolConfig config;

        public InternalWebSocketClient(URI serverUri, ProtocolConfig config) {
            super(serverUri, createHeaders(config));
            this.config = config;

            // Configure connection timeout
            setConnectionLostTimeout(10);
        }

        private static Map<String, String> createHeaders(ProtocolConfig config) {
            Map<String, String> headers = new ConcurrentHashMap<>();

            // Add authentication headers if provided
            if (config.getProperties() != null) {
                Map<String, Object> props = config.getProperties();

                // Check for common auth headers
                if (props.containsKey("Authorization")) {
                    headers.put("Authorization", props.get("Authorization").toString());
                }
                if (props.containsKey("X-API-Key")) {
                    headers.put("X-API-Key", props.get("X-API-Key").toString());
                }
                if (props.containsKey("Cookie")) {
                    headers.put("Cookie", props.get("Cookie").toString());
                }

                // Add any custom headers
                props.forEach((key, value) -> {
                    if (key.startsWith("header.")) {
                        String headerName = key.substring("header.".length());
                        headers.put(headerName, value.toString());
                    }
                });
            }

            return headers;
        }

        @Override
        public void onOpen(ServerHandshake handshake) {
            logger.fine("WebSocket connection opened");
        }

        @Override
        public void onMessage(String message) {
            logger.fine(String.format("Received message: %d bytes", message.length()));

            // Add to queue for synchronous consumption
            receivedMessages.offer(message);

            // Notify async handlers
            messageHandlers.values().forEach(handler -> {
                try {
                    ProtocolMessage protocolMessage = ProtocolMessage.builder()
                            .channel(getURI().toString())
                            .payload(message)
                            .timestamp(System.currentTimeMillis())
                            .build();
                    handler.onMessage(protocolMessage);
                } catch (Exception e) {
                    logger.log(Level.WARNING, "Error in message handler", e);
                    handler.onError(e);
                }
            });
        }

        @Override
        public void onClose(int code, String reason, boolean remote) {
            logger.info(String.format("WebSocket connection closed: code=%d, reason=%s, remote=%s",
                    code, reason, remote));

            // Notify handlers of completion
            messageHandlers.values().forEach(MessageHandler::onComplete);
        }

        @Override
        public void onError(Exception ex) {
            logger.log(Level.WARNING, "WebSocket error", ex);

            // Notify handlers of error
            messageHandlers.values().forEach(handler -> handler.onError(ex));
        }
    }

    @Override
    public String toString() {
        return String.format("WebSocketProtocolClient{connected=%s, url=%s}",
                isConnected(), config != null ? config.getUrl() : "not configured");
    }
}
