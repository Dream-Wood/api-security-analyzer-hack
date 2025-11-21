package active.protocol.mqtt;

import active.protocol.*;
import org.eclipse.paho.client.mqttv3.*;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.logging.Logger;

/**
 * Eclipse Paho MQTT protocol client for AsyncAPI security testing.
 */
public class MqttProtocolClient implements ProtocolClient {
    private static final Logger logger = Logger.getLogger(MqttProtocolClient.class.getName());

    private MqttClient client;
    private ProtocolConfig config;
    private final Map<String, MessageHandler> handlers = new ConcurrentHashMap<>();
    private final BlockingQueue<String> receivedMessages = new LinkedBlockingQueue<>();

    @Override
    public String getProtocol() {
        return "mqtt";
    }

    @Override
    public String getProtocolVersion() {
        return "3.1.1";
    }

    @Override
    public boolean isConnected() {
        return client != null && client.isConnected();
    }

    @Override
    public void connect(ProtocolConfig config) throws ProtocolException {
        this.config = config;
        try {
            String broker = config.getUrl().replaceFirst("mqtt://", "tcp://");
            String clientId = "api-sec-" + UUID.randomUUID().toString().substring(0, 8);
            client = new MqttClient(broker, clientId, new MemoryPersistence());

            MqttConnectOptions options = new MqttConnectOptions();
            options.setCleanSession(true);
            if (config.getProperties() != null) {
                if (config.getProperties().containsKey("username")) {
                    options.setUserName(config.getProperties().get("username").toString());
                }
                if (config.getProperties().containsKey("password")) {
                    options.setPassword(config.getProperties().get("password").toString().toCharArray());
                }
            }

            client.setCallback(new MqttCallback() {
                public void messageArrived(String topic, MqttMessage message) {
                    receivedMessages.offer(new String(message.getPayload()));
                    handlers.values().forEach(h -> {
                        try {
                            h.onMessage(ProtocolMessage.builder().payload(new String(message.getPayload())).build());
                        } catch (Exception e) {
                            h.onError(e);
                        }
                    });
                }
                public void connectionLost(Throwable cause) {}
                public void deliveryComplete(IMqttDeliveryToken token) {}
            });

            client.connect(options);
        } catch (Exception e) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.CONNECTION_FAILED, e.getMessage(), e);
        }
    }

    @Override
    public void disconnect() {
        if (client != null && client.isConnected()) {
            try {
                client.disconnect();
                client.close();
            } catch (Exception e) {
                logger.warning("Error disconnecting: " + e.getMessage());
            }
        }
    }

    @Override
    public ProtocolResponse send(ProtocolRequest request) throws ProtocolException {
        long start = System.currentTimeMillis();
        try {
            if (request.getType() == ProtocolRequest.RequestType.PUBLISH) {
                MqttMessage message = new MqttMessage(request.getPayload().getBytes());
                message.setQos(1);
                client.publish(request.getChannel(), message);
                return ProtocolResponse.builder().success(true).durationMs(System.currentTimeMillis() - start).build();
            } else if (request.getType() == ProtocolRequest.RequestType.SUBSCRIBE) {
                client.subscribe(request.getChannel());
                String msg = receivedMessages.poll(request.getTimeoutMs(), TimeUnit.MILLISECONDS);

                ProtocolResponse.Builder builder = ProtocolResponse.builder()
                        .success(true)
                        .durationMs(System.currentTimeMillis() - start);

                if (msg != null) {
                    ProtocolMessage protocolMessage = ProtocolMessage.builder()
                            .channel(request.getChannel())
                            .payload(msg)
                            .timestamp(System.currentTimeMillis())
                            .build();
                    builder.message(protocolMessage);
                }

                return builder.build();
            }
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PROTOCOL_ERROR, "Unsupported");
        } catch (Exception e) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PROTOCOL_ERROR, e.getMessage(), e);
        }
    }

    @Override
    public void subscribe(String channel, MessageHandler handler) throws ProtocolException {
        try {
            client.subscribe(channel);
            handlers.put(channel, handler);
        } catch (Exception e) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.SUBSCRIPTION_FAILED, e.getMessage(), e);
        }
    }

    @Override
    public void unsubscribe(String channel) throws ProtocolException {
        try {
            client.unsubscribe(channel);
            handlers.remove(channel);
        } catch (Exception e) {
            throw new ProtocolException(getProtocol(), ProtocolException.ErrorType.PROTOCOL_ERROR, e.getMessage(), e);
        }
    }

    @Override
    public void close() {
        disconnect();
    }

    @Override
    public String getDescription() {
        return "Eclipse Paho MQTT Protocol Client";
    }
}
