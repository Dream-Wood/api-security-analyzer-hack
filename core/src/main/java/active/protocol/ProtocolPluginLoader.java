package active.protocol;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Loads protocol client plugins from JAR files in the plugins directory.
 * Supports hotswap loading - new protocol plugins can be added without recompiling core.
 *
 * <p><b>Plugin Discovery:</b>
 * <ol>
 *   <li>Scans plugins/ directory for JAR files matching "protocol-*.jar"</li>
 *   <li>Creates isolated URLClassLoader for each JAR</li>
 *   <li>Uses ServiceLoader to discover ProtocolClient implementations</li>
 *   <li>Registers discovered clients in ProtocolRegistry</li>
 * </ol>
 *
 * <p><b>Plugin Structure:</b>
 * <pre>
 * plugins/
 * ├── protocol-websocket-1.0.jar
 * │   ├── META-INF/services/active.protocol.ProtocolClient
 * │   └── com/example/WebSocketProtocolClient.class
 * ├── protocol-kafka-2.0.jar
 * └── protocol-mqtt-1.0.jar
 * </pre>
 *
 * <p><b>ClassLoader Isolation:</b> Each plugin JAR gets its own URLClassLoader,
 * allowing different plugins to use different versions of dependencies.
 */
public class ProtocolPluginLoader {

    private static final Logger logger = Logger.getLogger(ProtocolPluginLoader.class.getName());
    private static final String PLUGIN_PREFIX = "protocol-";
    private static final String JAR_EXTENSION = ".jar";

    private final String pluginsDirectory;
    private final List<URLClassLoader> classLoaders;

    /**
     * Create a new protocol plugin loader.
     *
     * @param pluginsDirectory path to plugins directory
     */
    public ProtocolPluginLoader(String pluginsDirectory) {
        this.pluginsDirectory = pluginsDirectory != null ? pluginsDirectory : "plugins";
        this.classLoaders = new ArrayList<>();
    }

    /**
     * Create a protocol plugin loader with default plugins directory.
     */
    public ProtocolPluginLoader() {
        this("plugins");
    }

    /**
     * Discover and load all protocol client plugins.
     *
     * <p>This method performs two-phase discovery:
     * <ol>
     *   <li>Phase 1: Load classpath-based clients using ServiceLoader</li>
     *   <li>Phase 2: Load plugin-based clients from JAR files</li>
     * </ol>
     *
     * <p>All discovered clients are automatically registered in ProtocolRegistry.
     *
     * @return list of discovered protocol clients
     */
    public List<ProtocolClient> discoverProtocolClients() {
        List<ProtocolClient> allClients = new ArrayList<>();

        // Phase 1: Load classpath-based clients
        logger.info("Phase 1: Discovering classpath protocol clients");
        List<ProtocolClient> classpathClients = loadClasspathClients();
        allClients.addAll(classpathClients);
        logger.info(String.format("Found %d classpath protocol client(s)", classpathClients.size()));

        // Phase 2: Load plugin-based clients
        logger.info("Phase 2: Discovering plugin protocol clients from " + pluginsDirectory);
        List<ProtocolClient> pluginClients = loadPluginClients();
        allClients.addAll(pluginClients);
        logger.info(String.format("Found %d plugin protocol client(s)", pluginClients.size()));

        // Register all discovered clients
        ProtocolRegistry registry = ProtocolRegistry.getInstance();
        for (ProtocolClient client : allClients) {
            try {
                registry.register(client);
            } catch (Exception e) {
                logger.log(Level.WARNING,
                        String.format("Failed to register protocol client: %s", client.getProtocol()), e);
            }
        }

        logger.info(String.format("Total protocol clients discovered: %d", allClients.size()));
        return allClients;
    }

    /**
     * Load protocol clients from classpath using ServiceLoader.
     *
     * @return list of classpath protocol clients
     */
    private List<ProtocolClient> loadClasspathClients() {
        List<ProtocolClient> clients = new ArrayList<>();

        try {
            ServiceLoader<ProtocolClient> serviceLoader =
                    ServiceLoader.load(ProtocolClient.class, getClass().getClassLoader());

            for (ProtocolClient client : serviceLoader) {
                logger.info(String.format("Discovered classpath protocol client: %s (%s)",
                        client.getProtocol(), client.getClass().getName()));
                clients.add(client);
            }
        } catch (ServiceConfigurationError e) {
            logger.log(Level.WARNING, "Error loading classpath protocol clients", e);
        }

        return clients;
    }

    /**
     * Load protocol clients from plugin JAR files.
     *
     * @return list of plugin protocol clients
     */
    private List<ProtocolClient> loadPluginClients() {
        List<ProtocolClient> clients = new ArrayList<>();

        File pluginsDir = new File(pluginsDirectory);
        if (!pluginsDir.exists() || !pluginsDir.isDirectory()) {
            logger.warning(String.format("Plugins directory does not exist or is not a directory: %s",
                    pluginsDirectory));
            return clients;
        }

        File[] jarFiles = pluginsDir.listFiles((dir, name) ->
                name.startsWith(PLUGIN_PREFIX) && name.endsWith(JAR_EXTENSION));

        if (jarFiles == null || jarFiles.length == 0) {
            logger.info("No protocol plugin JARs found");
            return clients;
        }

        logger.info(String.format("Found %d protocol plugin JAR(s)", jarFiles.length));

        for (File jarFile : jarFiles) {
            try {
                List<ProtocolClient> pluginClients = loadClientsFromJar(jarFile);
                clients.addAll(pluginClients);
            } catch (Exception e) {
                logger.log(Level.WARNING,
                        String.format("Failed to load protocol clients from %s", jarFile.getName()), e);
            }
        }

        return clients;
    }

    /**
     * Load protocol clients from a single JAR file.
     *
     * @param jarFile the JAR file to load
     * @return list of protocol clients from this JAR
     * @throws Exception if loading fails
     */
    private List<ProtocolClient> loadClientsFromJar(File jarFile) throws Exception {
        List<ProtocolClient> clients = new ArrayList<>();

        logger.info(String.format("Loading protocol clients from: %s", jarFile.getName()));

        // Create isolated class loader for this plugin
        URL jarUrl = jarFile.toURI().toURL();
        URLClassLoader classLoader = new URLClassLoader(
                new URL[]{jarUrl},
                getClass().getClassLoader()
        );
        classLoaders.add(classLoader);

        // Use ServiceLoader to discover ProtocolClient implementations
        ServiceLoader<ProtocolClient> serviceLoader =
                ServiceLoader.load(ProtocolClient.class, classLoader);

        int count = 0;
        for (ProtocolClient client : serviceLoader) {
            logger.info(String.format("  Discovered: %s (%s) from %s",
                    client.getProtocol(),
                    client.getClass().getName(),
                    jarFile.getName()));
            clients.add(client);
            count++;
        }

        if (count == 0) {
            logger.warning(String.format("No ProtocolClient implementations found in %s", jarFile.getName()));
        }

        return clients;
    }

    /**
     * Close all plugin class loaders and release resources.
     * Should be called when shutting down the application.
     */
    public void close() {
        logger.info("Closing protocol plugin class loaders");

        for (URLClassLoader classLoader : classLoaders) {
            try {
                classLoader.close();
            } catch (Exception e) {
                logger.log(Level.WARNING, "Error closing class loader", e);
            }
        }

        classLoaders.clear();
    }

    /**
     * Get the plugins directory path.
     *
     * @return plugins directory path
     */
    public String getPluginsDirectory() {
        return pluginsDirectory;
    }

    /**
     * Get the number of active class loaders.
     *
     * @return class loader count
     */
    public int getClassLoaderCount() {
        return classLoaders.size();
    }
}
