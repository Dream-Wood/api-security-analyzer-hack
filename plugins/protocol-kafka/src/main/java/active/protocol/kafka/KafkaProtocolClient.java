package active.protocol.kafka;

import active.protocol.*;
import org.apache.kafka.clients.consumer.*;
import org.apache.kafka.clients.producer.*;
import org.apache.kafka.common.PartitionInfo;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.errors.WakeupException;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Production-ready Apache Kafka protocol client for AsyncAPI security testing.
 *
 * <p>Features:
 * <ul>
 *   <li>SASL/PLAIN, SASL/SCRAM authentication</li>
 *   <li>SSL/TLS encryption support</li>
 *   <li>Partition awareness and assignment</li>
 *   <li>Configurable offset management</li>
 *   <li>Consumer group management</li>
 *   <li>Producer acknowledgment handling</li>
 *   <li>Graceful shutdown and cleanup</li>
 * </ul>
 */
public class KafkaProtocolClient implements ProtocolClient {
    private static final Logger logger = Logger.getLogger(KafkaProtocolClient.class.getName());
    private static final int DEFAULT_POLL_TIMEOUT_MS = 5000;

    private KafkaProducer<String, String> producer;
    private KafkaConsumer<String, String> consumer;
    private ProtocolConfig config;
    private boolean connected = false;
    private final Map<String, MessageHandler> messageHandlers = new ConcurrentHashMap<>();
    private final ExecutorService consumerExecutor = Executors.newSingleThreadExecutor();
    private final AtomicBoolean consuming = new AtomicBoolean(false);

    @Override
    public String getProtocol() {
        return "kafka";
    }

    @Override
    public String getProtocolVersion() {
        return "3.6";
    }

    @Override
    public boolean isConnected() {
        return connected;
    }

    @Override
    public void connect(ProtocolConfig config) throws ProtocolException {
        this.config = config;
        try {
            // Parse bootstrap servers from URL
            String bootstrapServers = parseBootstrapServers(config.getUrl());
            logger.info(String.format("Connecting to Kafka bootstrap servers: %s", bootstrapServers));

            // Build producer configuration
            Properties producerProps = buildProducerConfig(bootstrapServers, config);
            logger.fine("Producer config: " + producerProps);

            try {
                producer = new KafkaProducer<>(producerProps);
            } catch (Exception e) {
                // Log the full cause chain for debugging
                Throwable cause = e;
                StringBuilder causeChain = new StringBuilder();
                while (cause != null) {
                    causeChain.append(cause.getClass().getName()).append(": ").append(cause.getMessage()).append(" -> ");
                    cause = cause.getCause();
                }
                logger.severe("Failed to construct kafka producer. Cause chain: " + causeChain);
                throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.CONNECTION_FAILED,
                        "Failed to construct kafka producer: " + e.getMessage() +
                        (e.getCause() != null ? " Caused by: " + e.getCause().getMessage() : ""), e);
            }

            // Build consumer configuration
            Properties consumerProps = buildConsumerConfig(bootstrapServers, config);
            logger.fine("Consumer config: " + consumerProps);
            consumer = new KafkaConsumer<>(consumerProps);

            connected = true;
            logger.info(String.format("Connected to Kafka cluster: %s", bootstrapServers));

        } catch (ProtocolException e) {
            throw e;
        } catch (Exception e) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.CONNECTION_FAILED,
                    "Failed to connect to Kafka: " + e.getMessage(), e);
        }
    }

    /**
     * Parse bootstrap servers from Kafka URL.
     */
    private String parseBootstrapServers(String url) {
        // Support formats: kafka://host:port, kafka://host1:port1,host2:port2
        return url.replaceFirst("kafka://", "")
                  .replaceFirst("kafka\\+ssl://", "");
    }

    /**
     * Build production-ready producer configuration.
     */
    private Properties buildProducerConfig(String bootstrapServers, ProtocolConfig config) {
        Properties props = new Properties();

        // Core settings
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        // Use class directly instead of getName() to work with shaded JAR
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class);

        // Reliability settings
        props.put(ProducerConfig.ACKS_CONFIG, "all"); // Wait for all replicas
        props.put(ProducerConfig.RETRIES_CONFIG, 3);
        props.put(ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION, 1); // Ensure ordering
        props.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true); // Exactly-once semantics

        // Performance settings
        props.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, "snappy");
        props.put(ProducerConfig.LINGER_MS_CONFIG, 10);
        props.put(ProducerConfig.BATCH_SIZE_CONFIG, 32768);

        // Timeout settings
        props.put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 30000);
        props.put(ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG, 120000);

        // Apply custom configuration
        applySecurityConfig(props, config);
        applyCustomProperties(props, config, "producer.");

        return props;
    }

    /**
     * Build production-ready consumer configuration.
     */
    private Properties buildConsumerConfig(String bootstrapServers, ProtocolConfig config) {
        Properties props = new Properties();

        // Core settings
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        // Use class directly instead of getName() to work with shaded JAR
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);

        // Consumer group settings
        String groupId = getProperty(config, "consumer.group.id", "api-security-analyzer-" + UUID.randomUUID());
        props.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG,
                getProperty(config, "consumer.auto.offset.reset", "earliest"));

        // Offset management
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG,
                getProperty(config, "consumer.enable.auto.commit", "true"));
        props.put(ConsumerConfig.AUTO_COMMIT_INTERVAL_MS_CONFIG, 5000);

        // Performance settings
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, 100);
        props.put(ConsumerConfig.FETCH_MIN_BYTES_CONFIG, 1024);
        props.put(ConsumerConfig.FETCH_MAX_WAIT_MS_CONFIG, 500);

        // Session and heartbeat
        props.put(ConsumerConfig.SESSION_TIMEOUT_MS_CONFIG, 30000);
        props.put(ConsumerConfig.HEARTBEAT_INTERVAL_MS_CONFIG, 10000);
        props.put(ConsumerConfig.MAX_POLL_INTERVAL_MS_CONFIG, 300000);

        // Apply custom configuration
        applySecurityConfig(props, config);
        applyCustomProperties(props, config, "consumer.");

        return props;
    }

    /**
     * Apply security configuration (SASL, SSL).
     */
    private void applySecurityConfig(Properties props, ProtocolConfig config) {
        if (config.getProperties() == null) {
            return;
        }

        Map<String, Object> configProps = config.getProperties();

        // SSL Configuration
        if (config.isEnableSsl() || config.getUrl().contains("kafka+ssl")) {
            props.put("security.protocol", "SSL");

            if (configProps.containsKey("ssl.truststore.location")) {
                props.put("ssl.truststore.location", configProps.get("ssl.truststore.location"));
            }
            if (configProps.containsKey("ssl.truststore.password")) {
                props.put("ssl.truststore.password", configProps.get("ssl.truststore.password"));
            }
            if (configProps.containsKey("ssl.keystore.location")) {
                props.put("ssl.keystore.location", configProps.get("ssl.keystore.location"));
            }
            if (configProps.containsKey("ssl.keystore.password")) {
                props.put("ssl.keystore.password", configProps.get("ssl.keystore.password"));
            }
            if (configProps.containsKey("ssl.key.password")) {
                props.put("ssl.key.password", configProps.get("ssl.key.password"));
            }
        }

        // SASL Configuration
        String saslMechanism = getProperty(config, "sasl.mechanism", null);
        if (saslMechanism != null) {
            props.put("security.protocol", "SASL_SSL");
            props.put("sasl.mechanism", saslMechanism);

            // SASL/PLAIN
            if ("PLAIN".equals(saslMechanism)) {
                String username = getProperty(config, "sasl.username", "");
                String password = getProperty(config, "sasl.password", "");
                String jaasConfig = String.format(
                    "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"%s\" password=\"%s\";",
                    username, password
                );
                props.put("sasl.jaas.config", jaasConfig);
            }

            // SASL/SCRAM-SHA-256 or SCRAM-SHA-512
            else if (saslMechanism.startsWith("SCRAM-SHA")) {
                String username = getProperty(config, "sasl.username", "");
                String password = getProperty(config, "sasl.password", "");
                String jaasConfig = String.format(
                    "org.apache.kafka.common.security.scram.ScramLoginModule required username=\"%s\" password=\"%s\";",
                    username, password
                );
                props.put("sasl.jaas.config", jaasConfig);
            }
        }
    }

    /**
     * Apply custom properties with prefix filter.
     */
    private void applyCustomProperties(Properties props, ProtocolConfig config, String prefix) {
        if (config.getProperties() == null) {
            return;
        }

        config.getProperties().forEach((key, value) -> {
            if (key.startsWith(prefix)) {
                String kafkaKey = key.substring(prefix.length());
                props.put(kafkaKey, value.toString());
            }
        });
    }

    /**
     * Get property value with default.
     */
    private String getProperty(ProtocolConfig config, String key, String defaultValue) {
        if (config.getProperties() == null) {
            return defaultValue;
        }
        Object value = config.getProperties().get(key);
        return value != null ? value.toString() : defaultValue;
    }

    @Override
    public void disconnect() {
        consuming.set(false);
        consumerExecutor.shutdown();

        try {
            if (!consumerExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                consumerExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            consumerExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }

        if (producer != null) {
            producer.close(Duration.ofSeconds(5));
        }
        if (consumer != null) {
            consumer.wakeup();
            consumer.close(Duration.ofSeconds(5));
        }

        messageHandlers.clear();
        connected = false;
        logger.info("Disconnected from Kafka cluster");
    }

    @Override
    public ProtocolResponse send(ProtocolRequest request) throws ProtocolException {
        if (!isConnected()) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PROTOCOL_ERROR,
                    "Not connected to Kafka cluster");
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
        String topic = request.getChannel();
        String payload = request.getPayload();

        logger.fine(String.format("Publishing to topic '%s': %d bytes", topic, payload.length()));

        try {
            ProducerRecord<String, String> record = new ProducerRecord<>(topic, payload);

            // Synchronous send with callback
            RecordMetadata metadata = producer.send(record).get();

            long duration = System.currentTimeMillis() - startTime;

            return ProtocolResponse.builder()
                    .success(true)
                    .statusCode(0)
                    .statusMessage("Message published successfully")
                    .durationMs(duration)
                    .metadata("topic", topic)
                    .metadata("partition", metadata.partition())
                    .metadata("offset", metadata.offset())
                    .metadata("timestamp", metadata.timestamp())
                    .build();

        } catch (Exception e) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PUBLISH_FAILED,
                    "Failed to publish message: " + e.getMessage(), e);
        }
    }

    private ProtocolResponse handleSubscribe(ProtocolRequest request, long startTime) throws ProtocolException {
        String topic = request.getChannel();
        int timeoutMs = request.getTimeoutMs() > 0 ? request.getTimeoutMs() : DEFAULT_POLL_TIMEOUT_MS;

        logger.fine(String.format("Subscribing to topic '%s' (timeout=%dms)", topic, timeoutMs));

        try {
            // Subscribe to topic
            consumer.subscribe(Collections.singletonList(topic));

            // Poll for messages
            ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(timeoutMs));

            long duration = System.currentTimeMillis() - startTime;

            if (!records.isEmpty()) {
                ConsumerRecord<String, String> firstRecord = records.iterator().next();

                ProtocolMessage protocolMessage = ProtocolMessage.builder()
                        .channel(firstRecord.topic())
                        .payload(firstRecord.value())
                        .timestamp(firstRecord.timestamp())
                        .metadata("partition", firstRecord.partition())
                        .metadata("offset", firstRecord.offset())
                        .build();

                return ProtocolResponse.builder()
                        .success(true)
                        .statusCode(0)
                        .statusMessage("Message received")
                        .message(protocolMessage)
                        .durationMs(duration)
                        .metadata("topic", firstRecord.topic())
                        .metadata("partition", firstRecord.partition())
                        .metadata("offset", firstRecord.offset())
                        .metadata("recordCount", records.count())
                        .build();
            } else {
                return ProtocolResponse.builder()
                        .success(true)
                        .statusCode(0)
                        .statusMessage("No messages within timeout")
                        .durationMs(duration)
                        .build();
            }

        } catch (WakeupException e) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.SUBSCRIPTION_FAILED,
                    "Consumer wakeup during subscription", e);
        } catch (Exception e) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.SUBSCRIPTION_FAILED,
                    "Failed to subscribe: " + e.getMessage(), e);
        }
    }

    private ProtocolResponse handleUnsubscribe(ProtocolRequest request, long startTime) {
        logger.fine("Unsubscribing from topics");

        consumer.unsubscribe();

        long duration = System.currentTimeMillis() - startTime;

        return ProtocolResponse.builder()
                .success(true)
                .statusCode(0)
                .statusMessage("Unsubscribed successfully")
                .durationMs(duration)
                .build();
    }

    @Override
    public void subscribe(String topic, MessageHandler handler) throws ProtocolException {
        if (!isConnected()) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PROTOCOL_ERROR,
                    "Not connected to Kafka cluster");
        }

        logger.fine(String.format("Setting up async subscription for topic '%s'", topic));

        messageHandlers.put(topic, handler);

        // Start async consumer if not already running
        if (consuming.compareAndSet(false, true)) {
            startAsyncConsumer(Collections.singletonList(topic));
        }
    }

    /**
     * Start async consumer in background thread.
     */
    private void startAsyncConsumer(List<String> topics) {
        consumerExecutor.submit(() -> {
            try {
                consumer.subscribe(topics);

                while (consuming.get()) {
                    ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(1000));

                    for (ConsumerRecord<String, String> record : records) {
                        MessageHandler handler = messageHandlers.get(record.topic());
                        if (handler != null) {
                            try {
                                ProtocolMessage message = ProtocolMessage.builder()
                                        .channel(record.topic())
                                        .payload(record.value())
                                        .timestamp(record.timestamp())
                                        .metadata("partition", record.partition())
                                        .metadata("offset", record.offset())
                                        .build();

                                handler.onMessage(message);
                            } catch (Exception e) {
                                logger.log(Level.WARNING, "Error in message handler", e);
                                handler.onError(e);
                            }
                        }
                    }
                }

                // Notify completion
                messageHandlers.values().forEach(MessageHandler::onComplete);

            } catch (WakeupException e) {
                logger.fine("Consumer wakeup called");
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Error in async consumer", e);
                messageHandlers.values().forEach(h -> h.onError(e));
            }
        });
    }

    @Override
    public void unsubscribe(String topic) throws ProtocolException {
        logger.fine(String.format("Removing subscription for topic '%s'", topic));

        messageHandlers.remove(topic);

        if (messageHandlers.isEmpty()) {
            consuming.set(false);
            consumer.unsubscribe();
        }
    }

    @Override
    public void close() {
        disconnect();
    }

    @Override
    public String getDescription() {
        return "Apache Kafka Protocol Client with SASL/SSL support";
    }

    @Override
    public String toString() {
        return String.format("KafkaProtocolClient{connected=%s, topics=%d}",
                isConnected(), messageHandlers.size());
    }
}
