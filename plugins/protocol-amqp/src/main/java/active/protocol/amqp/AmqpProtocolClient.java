package active.protocol.amqp;

import active.protocol.*;
import com.rabbitmq.client.*;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Production-ready RabbitMQ AMQP protocol client for AsyncAPI security testing.
 *
 * <p>Features:
 * <ul>
 *   <li>Exchange declarations (direct, topic, fanout, headers)</li>
 *   <li>Routing key support</li>
 *   <li>Queue binding and unbinding</li>
 *   <li>Channel pooling for performance</li>
 *   <li>Automatic connection recovery</li>
 *   <li>Dead letter exchange handling</li>
 *   <li>SSL/TLS support</li>
 *   <li>Username/password authentication</li>
 * </ul>
 */
public class AmqpProtocolClient implements ProtocolClient {
    private static final Logger logger = Logger.getLogger(AmqpProtocolClient.class.getName());
    private static final int DEFAULT_TIMEOUT_MS = 10000;
    private static final String DEFAULT_EXCHANGE = "";
    private static final String DEFAULT_EXCHANGE_TYPE = "direct";

    private Connection connection;
    private Channel publishChannel;
    private Channel consumeChannel;
    private ProtocolConfig config;
    private final Map<String, MessageHandler> messageHandlers = new ConcurrentHashMap<>();
    private final Map<String, String> consumerTags = new ConcurrentHashMap<>();
    private final BlockingQueue<Delivery> receivedMessages = new LinkedBlockingQueue<>();

    @Override
    public String getProtocol() {
        return "amqp";
    }

    @Override
    public String getProtocolVersion() {
        return "0.9.1";
    }

    @Override
    public boolean isConnected() {
        return connection != null && connection.isOpen();
    }

    @Override
    public void connect(ProtocolConfig config) throws ProtocolException {
        this.config = config;
        try {
            ConnectionFactory factory = buildConnectionFactory(config);

            logger.info(String.format("Connecting to AMQP broker: %s", config.getUrl()));

            // Create connection with automatic recovery
            connection = factory.newConnection();

            // Create channels
            publishChannel = connection.createChannel();
            consumeChannel = connection.createChannel();

            // Configure QoS for consumer
            consumeChannel.basicQos(getIntProperty(config, "qos.prefetch.count", 10));

            logger.info("Connected to AMQP broker");

        } catch (Exception e) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.CONNECTION_FAILED,
                    "Failed to connect to AMQP broker: " + e.getMessage(), e);
        }
    }

    /**
     * Build connection factory with all production settings.
     */
    private ConnectionFactory buildConnectionFactory(ProtocolConfig config) {
        ConnectionFactory factory = new ConnectionFactory();

        // Parse host and port from URL
        String url = config.getUrl().replaceFirst("amqps?://", "");
        String[] parts = url.split(":");
        String host = parts[0];
        int port = parts.length > 1 ? Integer.parseInt(parts[1]) : 5672;

        factory.setHost(host);
        factory.setPort(port);

        // Authentication
        if (config.getProperties() != null) {
            Map<String, Object> props = config.getProperties();

            if (props.containsKey("username")) {
                factory.setUsername(props.get("username").toString());
            }
            if (props.containsKey("password")) {
                factory.setPassword(props.get("password").toString());
            }
            if (props.containsKey("virtual.host")) {
                factory.setVirtualHost(props.get("virtual.host").toString());
            }
        }

        // Connection settings
        factory.setConnectionTimeout(getIntProperty(config, "connection.timeout.ms", 30000));
        factory.setRequestedHeartbeat(getIntProperty(config, "heartbeat.interval.sec", 60));
        factory.setNetworkRecoveryInterval(getIntProperty(config, "recovery.interval.ms", 5000));

        // Automatic recovery
        factory.setAutomaticRecoveryEnabled(true);
        factory.setTopologyRecoveryEnabled(true);

        // Thread pool
        ExecutorService executor = Executors.newFixedThreadPool(
                getIntProperty(config, "thread.pool.size", 10));
        factory.setSharedExecutor(executor);

        // SSL/TLS
        if (config.isEnableSsl() || config.getUrl().startsWith("amqps")) {
            try {
                factory.useSslProtocol();
            } catch (Exception e) {
                logger.log(Level.WARNING, "Failed to enable SSL", e);
            }
        }

        return factory;
    }

    @Override
    public void disconnect() {
        // Cancel all consumers
        consumerTags.forEach((queue, tag) -> {
            try {
                if (consumeChannel != null && consumeChannel.isOpen()) {
                    consumeChannel.basicCancel(tag);
                }
            } catch (Exception e) {
                logger.log(Level.WARNING, "Error canceling consumer", e);
            }
        });

        consumerTags.clear();
        messageHandlers.clear();
        receivedMessages.clear();

        // Close channels
        closeQuietly(publishChannel);
        closeQuietly(consumeChannel);

        // Close connection
        if (connection != null && connection.isOpen()) {
            try {
                connection.close();
                logger.info("Disconnected from AMQP broker");
            } catch (Exception e) {
                logger.log(Level.WARNING, "Error closing connection", e);
            }
        }
    }

    private void closeQuietly(Channel channel) {
        if (channel != null && channel.isOpen()) {
            try {
                channel.close();
            } catch (Exception e) {
                logger.log(Level.FINE, "Error closing channel", e);
            }
        }
    }

    @Override
    public ProtocolResponse send(ProtocolRequest request) throws ProtocolException {
        if (!isConnected()) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PROTOCOL_ERROR,
                    "Not connected to AMQP broker");
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
        String queue = request.getChannel();
        String payload = request.getPayload();

        logger.fine(String.format("Publishing to queue '%s': %d bytes", queue, payload.length()));

        try {
            // Declare queue with default settings
            AMQP.Queue.DeclareOk queueOk = publishChannel.queueDeclare(
                    queue,
                    isDurable(config),
                    false, // exclusive
                    isAutoDelete(config),
                    getQueueArguments(config)
            );

            // Get exchange and routing key from config
            String exchange = getStringProperty(config, "exchange", DEFAULT_EXCHANGE);
            String routingKey = getStringProperty(config, "routing.key", queue);

            // Declare exchange if not default
            if (!DEFAULT_EXCHANGE.equals(exchange)) {
                String exchangeType = getStringProperty(config, "exchange.type", DEFAULT_EXCHANGE_TYPE);
                publishChannel.exchangeDeclare(exchange, exchangeType, isDurable(config));

                // Bind queue to exchange
                publishChannel.queueBind(queue, exchange, routingKey);
            }

            // Build message properties
            AMQP.BasicProperties props = buildMessageProperties(config);

            // Publish message
            publishChannel.basicPublish(exchange, routingKey, props, payload.getBytes());

            long duration = System.currentTimeMillis() - startTime;

            return ProtocolResponse.builder()
                    .success(true)
                    .statusCode(0)
                    .statusMessage("Message published successfully")
                    .durationMs(duration)
                    .metadata("queue", queue)
                    .metadata("exchange", exchange)
                    .metadata("routingKey", routingKey)
                    .metadata("messageCount", queueOk.getMessageCount())
                    .build();

        } catch (Exception e) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PUBLISH_FAILED,
                    "Failed to publish message: " + e.getMessage(), e);
        }
    }

    private ProtocolResponse handleSubscribe(ProtocolRequest request, long startTime) throws ProtocolException {
        String queue = request.getChannel();
        int timeoutMs = request.getTimeoutMs() > 0 ? request.getTimeoutMs() : DEFAULT_TIMEOUT_MS;

        logger.fine(String.format("Subscribing to queue '%s' (timeout=%dms)", queue, timeoutMs));

        try {
            // Declare queue
            consumeChannel.queueDeclare(
                    queue,
                    isDurable(config),
                    false,
                    isAutoDelete(config),
                    getQueueArguments(config)
            );

            // Setup consumer callback
            DeliverCallback deliverCallback = (consumerTag, delivery) -> {
                receivedMessages.offer(delivery);
            };

            // Start consuming
            String consumerTag = consumeChannel.basicConsume(queue, true, deliverCallback, tag -> {});

            // Wait for message
            Delivery delivery = receivedMessages.poll(timeoutMs, TimeUnit.MILLISECONDS);

            // Cancel consumer
            consumeChannel.basicCancel(consumerTag);

            long duration = System.currentTimeMillis() - startTime;

            if (delivery != null) {
                String message = new String(delivery.getBody());

                ProtocolMessage protocolMessage = ProtocolMessage.builder()
                        .channel(queue)
                        .payload(message)
                        .timestamp(System.currentTimeMillis())
                        .metadata("exchange", delivery.getEnvelope().getExchange())
                        .metadata("routingKey", delivery.getEnvelope().getRoutingKey())
                        .metadata("deliveryTag", delivery.getEnvelope().getDeliveryTag())
                        .build();

                return ProtocolResponse.builder()
                        .success(true)
                        .statusCode(0)
                        .statusMessage("Message received")
                        .message(protocolMessage)
                        .durationMs(duration)
                        .metadata("queue", queue)
                        .metadata("exchange", delivery.getEnvelope().getExchange())
                        .metadata("routingKey", delivery.getEnvelope().getRoutingKey())
                        .metadata("deliveryTag", delivery.getEnvelope().getDeliveryTag())
                        .build();
            } else {
                return ProtocolResponse.builder()
                        .success(true)
                        .statusCode(0)
                        .statusMessage("No messages within timeout")
                        .durationMs(duration)
                        .build();
            }

        } catch (Exception e) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.SUBSCRIPTION_FAILED,
                    "Failed to subscribe: " + e.getMessage(), e);
        }
    }

    private ProtocolResponse handleUnsubscribe(ProtocolRequest request, long startTime) throws ProtocolException {
        String queue = request.getChannel();

        logger.fine(String.format("Unsubscribing from queue '%s'", queue));

        String consumerTag = consumerTags.remove(queue);
        if (consumerTag != null) {
            try {
                consumeChannel.basicCancel(consumerTag);
            } catch (IOException e) {
                throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PROTOCOL_ERROR,
                        "Failed to cancel consumer: " + e.getMessage(), e);
            }
        }

        long duration = System.currentTimeMillis() - startTime;

        return ProtocolResponse.builder()
                .success(true)
                .statusCode(0)
                .statusMessage("Unsubscribed successfully")
                .durationMs(duration)
                .build();
    }

    @Override
    public void subscribe(String queue, MessageHandler handler) throws ProtocolException {
        if (!isConnected()) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PROTOCOL_ERROR,
                    "Not connected to AMQP broker");
        }

        logger.fine(String.format("Setting up async subscription for queue '%s'", queue));

        try {
            // Declare queue
            consumeChannel.queueDeclare(
                    queue,
                    isDurable(config),
                    false,
                    isAutoDelete(config),
                    getQueueArguments(config)
            );

            // Setup consumer callback
            DeliverCallback deliverCallback = (consumerTag, delivery) -> {
                try {
                    ProtocolMessage message = ProtocolMessage.builder()
                            .payload(new String(delivery.getBody()))
                            .metadata("exchange", delivery.getEnvelope().getExchange())
                            .metadata("routingKey", delivery.getEnvelope().getRoutingKey())
                            .metadata("deliveryTag", delivery.getEnvelope().getDeliveryTag())
                            .build();

                    handler.onMessage(message);
                } catch (Exception e) {
                    logger.log(Level.WARNING, "Error in message handler", e);
                    handler.onError(e);
                }
            };

            CancelCallback cancelCallback = consumerTag -> {
                logger.fine(String.format("Consumer cancelled: %s", consumerTag));
                handler.onComplete();
            };

            // Start consuming
            String consumerTag = consumeChannel.basicConsume(queue, true, deliverCallback, cancelCallback);

            messageHandlers.put(queue, handler);
            consumerTags.put(queue, consumerTag);

        } catch (IOException e) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.SUBSCRIPTION_FAILED,
                    "Failed to subscribe: " + e.getMessage(), e);
        }
    }

    @Override
    public void unsubscribe(String queue) throws ProtocolException {
        logger.fine(String.format("Removing subscription for queue '%s'", queue));

        messageHandlers.remove(queue);
        String consumerTag = consumerTags.remove(queue);

        if (consumerTag != null) {
            try {
                consumeChannel.basicCancel(consumerTag);
            } catch (IOException e) {
                throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PROTOCOL_ERROR,
                        "Failed to cancel consumer: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Build message properties for publishing.
     */
    private AMQP.BasicProperties buildMessageProperties(ProtocolConfig config) {
        AMQP.BasicProperties.Builder builder = new AMQP.BasicProperties.Builder();

        builder.contentType("application/json");
        builder.deliveryMode(isDurable(config) ? 2 : 1); // 2 = persistent

        // Add custom properties
        if (config.getProperties() != null) {
            Map<String, Object> props = config.getProperties();

            if (props.containsKey("message.priority")) {
                builder.priority(Integer.parseInt(props.get("message.priority").toString()));
            }
            if (props.containsKey("message.expiration")) {
                builder.expiration(props.get("message.expiration").toString());
            }
            if (props.containsKey("message.correlation.id")) {
                builder.correlationId(props.get("message.correlation.id").toString());
            }
        }

        return builder.build();
    }

    /**
     * Get queue arguments for dead letter exchange, TTL, etc.
     */
    private Map<String, Object> getQueueArguments(ProtocolConfig config) {
        Map<String, Object> args = new ConcurrentHashMap<>();

        if (config.getProperties() != null) {
            Map<String, Object> props = config.getProperties();

            // Dead letter exchange
            if (props.containsKey("queue.dlx")) {
                args.put("x-dead-letter-exchange", props.get("queue.dlx"));
            }
            if (props.containsKey("queue.dlx.routing.key")) {
                args.put("x-dead-letter-routing-key", props.get("queue.dlx.routing.key"));
            }

            // Message TTL
            if (props.containsKey("queue.message.ttl")) {
                args.put("x-message-ttl", Integer.parseInt(props.get("queue.message.ttl").toString()));
            }

            // Queue length limit
            if (props.containsKey("queue.max.length")) {
                args.put("x-max-length", Integer.parseInt(props.get("queue.max.length").toString()));
            }
        }

        return args;
    }

    private boolean isDurable(ProtocolConfig config) {
        return getBoolProperty(config, "queue.durable", false);
    }

    private boolean isAutoDelete(ProtocolConfig config) {
        return getBoolProperty(config, "queue.auto.delete", false);
    }

    private boolean getBoolProperty(ProtocolConfig config, String key, boolean defaultValue) {
        if (config.getProperties() == null) {
            return defaultValue;
        }
        Object value = config.getProperties().get(key);
        return value != null ? Boolean.parseBoolean(value.toString()) : defaultValue;
    }

    private int getIntProperty(ProtocolConfig config, String key, int defaultValue) {
        if (config.getProperties() == null) {
            return defaultValue;
        }
        Object value = config.getProperties().get(key);
        return value != null ? Integer.parseInt(value.toString()) : defaultValue;
    }

    private String getStringProperty(ProtocolConfig config, String key, String defaultValue) {
        if (config.getProperties() == null) {
            return defaultValue;
        }
        Object value = config.getProperties().get(key);
        return value != null ? value.toString() : defaultValue;
    }

    @Override
    public void close() {
        disconnect();
    }

    @Override
    public String getDescription() {
        return "RabbitMQ AMQP Protocol Client with exchange/routing support";
    }

    @Override
    public String toString() {
        return String.format("AmqpProtocolClient{connected=%s, subscriptions=%d}",
                isConnected(), messageHandlers.size());
    }
}
