package active.protocol;

/**
 * Base interface for all async protocol clients (Kafka, MQTT, WebSocket, AMQP, etc.).
 * Protocol clients are loaded as hotswap plugins and registered in ProtocolRegistry.
 *
 * <p>Implementations must be thread-safe as they may be used concurrently by multiple scanners.
 *
 * <p><b>Lifecycle:</b>
 * <ol>
 *   <li>Create client instance</li>
 *   <li>Call connect() to establish connection</li>
 *   <li>Use send(), publish(), subscribe() for operations</li>
 *   <li>Call disconnect() or close() to cleanup resources</li>
 * </ol>
 *
 * <p><b>Connection Pooling:</b> Implementations should handle connection pooling internally
 * if needed for their protocol. The AsyncAnalysisEngine may reuse the same client instance
 * for multiple operations.
 *
 * <p><b>Reconnection:</b> Implementations should handle reconnection logic transparently
 * when possible, or throw ProtocolException with appropriate error type.
 */
public interface ProtocolClient extends AutoCloseable {

    /**
     * Get the protocol name (e.g., "kafka", "mqtt", "ws", "amqp").
     *
     * @return protocol name in lowercase
     */
    String getProtocol();

    /**
     * Get the protocol version supported by this client (e.g., "2.8", "3.1.1", "13").
     * Optional: may return null if version is not applicable.
     *
     * @return protocol version or null
     */
    default String getProtocolVersion() {
        return null;
    }

    /**
     * Check if the client is currently connected.
     *
     * @return true if connected, false otherwise
     */
    boolean isConnected();

    /**
     * Connect to the protocol server/broker using the provided configuration.
     *
     * <p>This method should be idempotent - calling it multiple times should not
     * create multiple connections.
     *
     * @param config connection configuration
     * @throws ProtocolException if connection fails
     */
    void connect(ProtocolConfig config) throws ProtocolException;

    /**
     * Disconnect from the protocol server/broker.
     * Should gracefully close connections and cleanup resources.
     *
     * <p>This method should be idempotent - calling it on already disconnected
     * client should not throw exception.
     */
    void disconnect();

    /**
     * Send a request and receive a response.
     * This is the main method for request-reply patterns and one-way operations.
     *
     * <p>For PUBLISH operations, the response indicates success/failure.
     * For SUBSCRIBE operations, the response may contain received messages.
     *
     * @param request the protocol request
     * @return the protocol response
     * @throws ProtocolException if operation fails
     */
    ProtocolResponse send(ProtocolRequest request) throws ProtocolException;

    /**
     * Publish a message to a channel/topic.
     * Convenience method equivalent to send() with PUBLISH request type.
     *
     * @param channel the channel/topic name
     * @param message the message to publish
     * @throws ProtocolException if publish fails
     */
    default void publish(String channel, ProtocolMessage message) throws ProtocolException {
        ProtocolRequest request = ProtocolRequest.builder()
                .type(ProtocolRequest.RequestType.PUBLISH)
                .channel(channel)
                .payload(message.getPayload())
                .contentType(message.getContentType())
                .headers(message.getHeaders())
                .build();

        ProtocolResponse response = send(request);
        if (!response.isSuccess()) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PUBLISH_FAILED,
                    "Failed to publish message: " + response.getStatusMessage());
        }
    }

    /**
     * Subscribe to a channel/topic and receive messages via callback.
     *
     * <p>Note: This is an asynchronous operation. Messages will be delivered
     * to the handler callback as they arrive.
     *
     * @param channel the channel/topic name
     * @param handler the message handler callback
     * @throws ProtocolException if subscription fails
     */
    default void subscribe(String channel, MessageHandler handler) throws ProtocolException {
        throw new UnsupportedOperationException(
                "Subscribe operation is not supported by " + getProtocol() + " client");
    }

    /**
     * Unsubscribe from a channel/topic.
     *
     * @param channel the channel/topic name
     * @throws ProtocolException if unsubscribe fails
     */
    default void unsubscribe(String channel) throws ProtocolException {
        throw new UnsupportedOperationException(
                "Unsubscribe operation is not supported by " + getProtocol() + " client");
    }

    /**
     * Close the client and release all resources.
     * This is called automatically when using try-with-resources.
     *
     * <p>Implementation should call disconnect() and cleanup any remaining resources.
     */
    @Override
    default void close() {
        if (isConnected()) {
            disconnect();
        }
    }

    /**
     * Get a description of this protocol client implementation.
     * Used for logging and debugging purposes.
     *
     * @return description of the client
     */
    default String getDescription() {
        return String.format("%s Protocol Client", getProtocol().toUpperCase());
    }
}
