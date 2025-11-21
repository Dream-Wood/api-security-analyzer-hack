package active.async;

import active.protocol.*;
import active.scanner.ScanContext;
import active.scanner.ScanIntensity;
import model.AsyncOperationSpec;
import model.ChannelSpec;
import model.ServerSpec;

import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Engine for performing active security analysis on AsyncAPI specifications.
 * Orchestrates protocol clients, async scanners, and scan execution for async operations.
 *
 * <p><b>Key Features:</b>
 * <ul>
 *   <li>Multi-protocol support (Kafka, MQTT, WebSocket, AMQP, etc.)</li>
 *   <li>Parallel operation scanning with thread pool</li>
 *   <li>Protocol client management and connection pooling</li>
 *   <li>Hotswap scanner plugins</li>
 *   <li>Progress callbacks</li>
 * </ul>
 *
 * <p><b>Usage Example:</b>
 * <pre>
 * AsyncAnalysisEngine engine = new AsyncAnalysisEngine.Builder()
 *     .withThreadPool(10)
 *     .withPluginsDirectory("plugins")
 *     .withIntensity(ScanIntensity.MEDIUM)
 *     .build();
 *
 * AsyncAnalysisReport report = engine.analyze(channels, servers);
 * engine.shutdown();
 * </pre>
 */
public class AsyncAnalysisEngine {

    private static final Logger logger = Logger.getLogger(AsyncAnalysisEngine.class.getName());

    private final ExecutorService threadPool;
    private final ProtocolRegistry protocolRegistry;
    private final AsyncScannerRegistry scannerRegistry;
    private final ScanContext scanContext;
    private final Map<String, ProtocolClient> activeClients;
    private final boolean autoDiscoverPlugins;

    private AsyncAnalysisEngine(Builder builder) {
        this.threadPool = builder.threadPool != null
                ? builder.threadPool
                : Executors.newFixedThreadPool(builder.threadPoolSize);
        this.protocolRegistry = ProtocolRegistry.getInstance();
        this.scannerRegistry = AsyncScannerRegistry.getInstance();
        this.scanContext = builder.scanContext;
        this.activeClients = new ConcurrentHashMap<>();
        this.autoDiscoverPlugins = builder.autoDiscoverPlugins;

        if (autoDiscoverPlugins) {
            discoverPlugins(builder.pluginsDirectory);
        }
    }

    /**
     * Discover and load protocol clients and scanners from plugins directory.
     *
     * @param pluginsDirectory path to plugins directory
     */
    private void discoverPlugins(String pluginsDirectory) {
        logger.info("Discovering async protocol and scanner plugins");

        // Discover protocol clients
        ProtocolPluginLoader protocolLoader = new ProtocolPluginLoader(pluginsDirectory);
        List<ProtocolClient> clients = protocolLoader.discoverProtocolClients();
        logger.info(String.format("Discovered %d protocol client(s)", clients.size()));

        // Discover async scanners
        AsyncScannerAutoDiscovery scannerDiscovery = new AsyncScannerAutoDiscovery(pluginsDirectory);
        List<AsyncVulnerabilityScanner> scanners = scannerDiscovery.discoverAndRegister();
        logger.info(String.format("Discovered %d async scanner(s)", scanners.size()));
    }

    /**
     * Analyze AsyncAPI channels for vulnerabilities.
     *
     * @param channels list of AsyncAPI channels
     * @param servers  map of server specifications
     * @return analysis report with findings
     */
    public AsyncAnalysisReport analyze(List<ChannelSpec> channels, Map<String, ServerSpec> servers) {
        logger.info(String.format("Starting AsyncAPI active analysis for %d channel(s)", channels.size()));

        long startTime = System.currentTimeMillis();
        List<AsyncScanResult> allResults = new ArrayList<>();
        List<Future<List<AsyncScanResult>>> futures = new ArrayList<>();

        try {
            // Submit scan tasks for each channel operation
            for (ChannelSpec channel : channels) {
                for (AsyncOperationSpec operation : channel.getAllOperations()) {
                    Future<List<AsyncScanResult>> future =
                            threadPool.submit(() -> scanOperation(operation, channel, servers));
                    futures.add(future);
                }
            }

            // Collect results
            for (Future<List<AsyncScanResult>> future : futures) {
                try {
                    List<AsyncScanResult> results = future.get();
                    allResults.addAll(results);
                } catch (ExecutionException e) {
                    logger.log(Level.SEVERE, "Error executing scan task", e.getCause());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    logger.warning("Scan task interrupted");
                }
            }

        } finally {
            // Cleanup protocol clients
            closeAllClients();
        }

        long duration = System.currentTimeMillis() - startTime;
        logger.info(String.format("AsyncAPI active analysis completed in %dms", duration));

        return new AsyncAnalysisReport(allResults, duration);
    }

    /**
     * Scan a single async operation for vulnerabilities.
     *
     * @param operation the operation to scan
     * @param channel   the channel containing the operation
     * @param servers   server specifications
     * @return list of scan results
     */
    private List<AsyncScanResult> scanOperation(
            AsyncOperationSpec operation,
            ChannelSpec channel,
            Map<String, ServerSpec> servers) {

        List<AsyncScanResult> results = new ArrayList<>();

        try {
            // Resolve server for this operation
            ServerSpec server = resolveServer(channel, servers);
            if (server == null) {
                logger.warning(String.format("No server found for channel: %s", channel.getName()));
                return results;
            }

            String protocol = server.getProtocol();
            logger.fine(String.format("Scanning operation %s/%s on protocol %s",
                    channel.getName(), operation.getOperationType(), protocol));

            // Get or create protocol client
            ProtocolClient client = getOrCreateClient(server);
            if (client == null) {
                logger.warning(String.format("No protocol client available for: %s", protocol));
                return results;
            }

            // Get applicable scanners
            List<AsyncVulnerabilityScanner> scanners =
                    scannerRegistry.getApplicableScanners(operation, protocol);

            logger.fine(String.format("Found %d applicable scanner(s) for %s/%s",
                    scanners.size(), channel.getName(), operation.getOperationType()));

            // Execute each scanner
            for (AsyncVulnerabilityScanner scanner : scanners) {
                try {
                    AsyncScanResult result = scanner.scan(operation, client, scanContext);
                    results.add(result);

                    if (result.hasVulnerabilities()) {
                        logger.info(String.format("Scanner '%s' found %d vulnerabilitie(s) in %s/%s",
                                scanner.getName(), result.getVulnerabilityCount(),
                                channel.getName(), operation.getOperationType()));
                    }

                } catch (Exception e) {
                    logger.log(Level.WARNING,
                            String.format("Error executing scanner %s", scanner.getName()), e);
                }
            }

        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error scanning operation", e);
        }

        return results;
    }

    /**
     * Resolve the server for a channel.
     *
     * @param channel the channel
     * @param servers available servers
     * @return the server spec, or null if not found
     */
    private ServerSpec resolveServer(ChannelSpec channel, Map<String, ServerSpec> servers) {
        if (servers == null || servers.isEmpty()) {
            return null;
        }

        // If channel specifies servers, use the first one
        List<String> channelServers = channel.getServers();
        if (channelServers != null && !channelServers.isEmpty()) {
            String serverName = channelServers.get(0);
            return servers.get(serverName);
        }

        // Otherwise, use the first available server
        return servers.values().iterator().next();
    }

    /**
     * Get or create a protocol client for a server.
     *
     * @param server the server spec
     * @return the protocol client, or null if not available
     */
    private ProtocolClient getOrCreateClient(ServerSpec server) {
        String protocol = server.getProtocol().toLowerCase();
        String clientKey = server.getName() != null ? server.getName() : server.getUrl();

        // Check if we already have a client for this server
        ProtocolClient client = activeClients.get(clientKey);
        if (client != null && client.isConnected()) {
            return client;
        }

        // Get a new client from registry
        client = protocolRegistry.getClient(protocol);
        if (client == null) {
            logger.warning(String.format("No protocol client registered for: %s", protocol));
            return null;
        }

        // Connect the client
        try {
            ProtocolConfig config = buildProtocolConfig(server);
            client.connect(config);
            activeClients.put(clientKey, client);
            logger.fine(String.format("Connected to %s server: %s", protocol, server.getUrl()));
            return client;

        } catch (ProtocolException e) {
            logger.log(Level.WARNING,
                    String.format("Failed to connect to %s: %s", server.getUrl(), e.getMessage()), e);
            return null;
        }
    }

    /**
     * Build protocol configuration from server spec.
     *
     * @param server the server spec
     * @return protocol configuration
     */
    private ProtocolConfig buildProtocolConfig(ServerSpec server) {
        ProtocolConfig.Builder configBuilder = ProtocolConfig.builder(server.getProtocol())
                .url(server.getUrl());

        // Add protocol version if available
        if (server.getProtocolVersion() != null) {
            configBuilder.property("version", server.getProtocolVersion());
        }

        // Enable SSL for secure protocols
        if (server.isSecure()) {
            configBuilder.enableSsl(true);
        }

        // Add server variables as properties
        if (server.getVariables() != null) {
            configBuilder.properties(server.getVariables());
        }

        // Add bindings as properties
        if (server.getBindings() != null) {
            configBuilder.properties(server.getBindings());
        }

        // TODO: Add authentication from scan context

        return configBuilder.build();
    }

    /**
     * Close all active protocol clients.
     */
    private void closeAllClients() {
        logger.fine("Closing all protocol clients");

        for (ProtocolClient client : activeClients.values()) {
            try {
                client.close();
            } catch (Exception e) {
                logger.log(Level.WARNING, "Error closing protocol client", e);
            }
        }

        activeClients.clear();
    }

    /**
     * Shutdown the analysis engine and release resources.
     */
    public void shutdown() {
        logger.info("Shutting down AsyncAnalysisEngine");

        closeAllClients();

        threadPool.shutdown();
        try {
            if (!threadPool.awaitTermination(30, TimeUnit.SECONDS)) {
                threadPool.shutdownNow();
            }
        } catch (InterruptedException e) {
            threadPool.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Builder for creating AsyncAnalysisEngine instances.
     */
    public static class Builder {
        private ExecutorService threadPool;
        private int threadPoolSize = 10;
        private ScanContext scanContext;
        private String pluginsDirectory = "plugins";
        private boolean autoDiscoverPlugins = true;

        public Builder withThreadPool(ExecutorService threadPool) {
            this.threadPool = threadPool;
            return this;
        }

        public Builder withThreadPoolSize(int size) {
            this.threadPoolSize = size;
            return this;
        }

        public Builder withScanContext(ScanContext context) {
            this.scanContext = context;
            return this;
        }

        public Builder withIntensity(ScanIntensity intensity) {
            if (this.scanContext == null) {
                this.scanContext = ScanContext.builder().build();
            }
            // Note: ScanContext is immutable, need to rebuild
            this.scanContext = ScanContext.builder()
                    .scanIntensity(intensity)
                    .build();
            return this;
        }

        public Builder withPluginsDirectory(String directory) {
            this.pluginsDirectory = directory;
            return this;
        }

        public Builder withAutoDiscoverPlugins(boolean autoDiscover) {
            this.autoDiscoverPlugins = autoDiscover;
            return this;
        }

        public AsyncAnalysisEngine build() {
            if (scanContext == null) {
                scanContext = ScanContext.builder().build();
            }
            return new AsyncAnalysisEngine(this);
        }
    }
}
