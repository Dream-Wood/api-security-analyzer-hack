package active.protocol;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Thread-safe registry for managing protocol client implementations.
 * Protocol clients are loaded as hotswap plugins and registered here for use by AsyncAnalysisEngine.
 *
 * <p>The registry maintains a mapping of protocol names (e.g., "kafka", "mqtt", "ws")
 * to their corresponding ProtocolClient implementations.
 *
 * <p><b>Thread Safety:</b> All operations are thread-safe using ConcurrentHashMap.
 *
 * <p><b>Usage Example:</b>
 * <pre>
 * ProtocolRegistry registry = ProtocolRegistry.getInstance();
 * registry.register(new KafkaProtocolClient());
 * registry.register(new MqttProtocolClient());
 *
 * ProtocolClient client = registry.getClient("kafka");
 * if (client != null) {
 *     client.connect(config);
 *     // Use client...
 * }
 * </pre>
 */
public class ProtocolRegistry {

    private static final Logger logger = Logger.getLogger(ProtocolRegistry.class.getName());
    private static final ProtocolRegistry INSTANCE = new ProtocolRegistry();

    private final Map<String, ProtocolClient> clients;
    private final Map<String, String> protocolDescriptions;

    private ProtocolRegistry() {
        this.clients = new ConcurrentHashMap<>();
        this.protocolDescriptions = new ConcurrentHashMap<>();
    }

    /**
     * Get the singleton instance of the registry.
     *
     * @return the registry instance
     */
    public static ProtocolRegistry getInstance() {
        return INSTANCE;
    }

    /**
     * Register a protocol client in the registry.
     *
     * <p>If a client for this protocol already exists, it will be replaced
     * and a warning will be logged.
     *
     * @param client the protocol client to register
     * @throws IllegalArgumentException if client is null or protocol name is invalid
     */
    public void register(ProtocolClient client) {
        if (client == null) {
            throw new IllegalArgumentException("Protocol client cannot be null");
        }

        String protocol = client.getProtocol();
        if (protocol == null || protocol.trim().isEmpty()) {
            throw new IllegalArgumentException("Protocol name cannot be null or empty");
        }

        String normalizedProtocol = protocol.toLowerCase().trim();

        if (clients.containsKey(normalizedProtocol)) {
            logger.warning(String.format(
                    "Protocol client for '%s' already registered, replacing with %s",
                    normalizedProtocol, client.getClass().getName()));
        }

        clients.put(normalizedProtocol, client);
        protocolDescriptions.put(normalizedProtocol, client.getDescription());

        logger.info(String.format("Registered protocol client: %s (%s)",
                normalizedProtocol, client.getClass().getName()));
    }

    /**
     * Unregister a protocol client from the registry.
     *
     * @param protocol the protocol name to unregister
     * @return true if a client was removed, false if not found
     */
    public boolean unregister(String protocol) {
        if (protocol == null) {
            return false;
        }

        String normalizedProtocol = protocol.toLowerCase().trim();
        ProtocolClient removed = clients.remove(normalizedProtocol);
        protocolDescriptions.remove(normalizedProtocol);

        if (removed != null) {
            logger.info(String.format("Unregistered protocol client: %s", normalizedProtocol));
            return true;
        }

        return false;
    }

    /**
     * Get a protocol client for the specified protocol.
     *
     * @param protocol the protocol name (case-insensitive)
     * @return the protocol client, or null if not found
     */
    public ProtocolClient getClient(String protocol) {
        if (protocol == null) {
            return null;
        }

        String normalizedProtocol = protocol.toLowerCase().trim();
        return clients.get(normalizedProtocol);
    }

    /**
     * Check if a protocol client is registered for the specified protocol.
     *
     * @param protocol the protocol name
     * @return true if a client is registered
     */
    public boolean hasClient(String protocol) {
        if (protocol == null) {
            return false;
        }

        String normalizedProtocol = protocol.toLowerCase().trim();
        return clients.containsKey(normalizedProtocol);
    }

    /**
     * Get all registered protocol names.
     *
     * @return unmodifiable set of protocol names
     */
    public Set<String> getRegisteredProtocols() {
        return Collections.unmodifiableSet(clients.keySet());
    }

    /**
     * Get all registered protocol clients.
     *
     * @return unmodifiable collection of protocol clients
     */
    public Collection<ProtocolClient> getAllClients() {
        return Collections.unmodifiableCollection(clients.values());
    }

    /**
     * Get the number of registered protocol clients.
     *
     * @return count of registered clients
     */
    public int getClientCount() {
        return clients.size();
    }

    /**
     * Clear all registered protocol clients.
     * Useful for testing or reinitialization.
     */
    public void clear() {
        logger.info("Clearing all protocol clients from registry");
        clients.clear();
        protocolDescriptions.clear();
    }

    /**
     * Get a summary of all registered protocols.
     *
     * @return map of protocol names to descriptions
     */
    public Map<String, String> getProtocolDescriptions() {
        return Collections.unmodifiableMap(protocolDescriptions);
    }

    /**
     * Get a formatted string representation of all registered protocols.
     *
     * @return formatted string with protocol information
     */
    public String getRegistryInfo() {
        if (clients.isEmpty()) {
            return "No protocol clients registered";
        }

        StringBuilder info = new StringBuilder();
        info.append(String.format("Registered Protocol Clients (%d):\n", clients.size()));

        List<String> sortedProtocols = new ArrayList<>(clients.keySet());
        Collections.sort(sortedProtocols);

        for (String protocol : sortedProtocols) {
            ProtocolClient client = clients.get(protocol);
            String version = client.getProtocolVersion();
            String versionStr = version != null ? " v" + version : "";

            info.append(String.format("  - %s%s: %s (%s)\n",
                    protocol,
                    versionStr,
                    protocolDescriptions.get(protocol),
                    client.getClass().getSimpleName()));
        }

        return info.toString();
    }

    /**
     * Validate that required protocols are available.
     *
     * @param requiredProtocols list of required protocol names
     * @return list of missing protocols (empty if all are available)
     */
    public List<String> validateRequiredProtocols(List<String> requiredProtocols) {
        if (requiredProtocols == null || requiredProtocols.isEmpty()) {
            return Collections.emptyList();
        }

        return requiredProtocols.stream()
                .map(String::toLowerCase)
                .map(String::trim)
                .filter(protocol -> !clients.containsKey(protocol))
                .collect(Collectors.toList());
    }

    @Override
    public String toString() {
        return String.format("ProtocolRegistry{clients=%d, protocols=%s}",
                clients.size(), getRegisteredProtocols());
    }
}
