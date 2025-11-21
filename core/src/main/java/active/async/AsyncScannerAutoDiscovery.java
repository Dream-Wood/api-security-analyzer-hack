package active.async;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Discovers and loads async vulnerability scanner plugins using two-phase approach:
 * <ol>
 *   <li>Phase 1: Load classpath-based scanners using ServiceLoader</li>
 *   <li>Phase 2: Load plugin-based scanners from JAR files in plugins/ directory</li>
 * </ol>
 *
 * <p><b>Plugin Structure:</b>
 * <pre>
 * plugins/
 * ├── scanner-async-auth-1.0.jar
 * │   ├── META-INF/services/active.async.AsyncVulnerabilityScanner
 * │   └── com/example/UnauthorizedSubscriptionScanner.class
 * ├── scanner-async-injection-1.0.jar
 * └── scanner-async-replay-1.0.jar
 * </pre>
 */
public class AsyncScannerAutoDiscovery {

    private static final Logger logger = Logger.getLogger(AsyncScannerAutoDiscovery.class.getName());
    private static final String PLUGIN_PREFIX = "scanner-async-";
    private static final String JAR_EXTENSION = ".jar";

    private final String pluginsDirectory;
    private final List<URLClassLoader> classLoaders;

    /**
     * Create a new async scanner auto-discovery instance.
     *
     * @param pluginsDirectory path to plugins directory
     */
    public AsyncScannerAutoDiscovery(String pluginsDirectory) {
        this.pluginsDirectory = pluginsDirectory != null ? pluginsDirectory : "plugins";
        this.classLoaders = new ArrayList<>();
    }

    /**
     * Create an async scanner auto-discovery with default plugins directory.
     */
    public AsyncScannerAutoDiscovery() {
        this("plugins");
    }

    /**
     * Discover and register all async vulnerability scanners.
     *
     * @return list of discovered scanners
     */
    public List<AsyncVulnerabilityScanner> discoverAndRegister() {
        List<AsyncVulnerabilityScanner> allScanners = new ArrayList<>();

        // Phase 1: Load classpath-based scanners
        logger.info("Phase 1: Discovering classpath async scanners");
        List<AsyncVulnerabilityScanner> classpathScanners = loadClasspathScanners();
        allScanners.addAll(classpathScanners);
        logger.info(String.format("Found %d classpath async scanner(s)", classpathScanners.size()));

        // Phase 2: Load plugin-based scanners
        logger.info("Phase 2: Discovering plugin async scanners from " + pluginsDirectory);
        List<AsyncVulnerabilityScanner> pluginScanners = loadPluginScanners();
        allScanners.addAll(pluginScanners);
        logger.info(String.format("Found %d plugin async scanner(s)", pluginScanners.size()));

        // Register all discovered scanners
        AsyncScannerRegistry registry = AsyncScannerRegistry.getInstance();
        for (AsyncVulnerabilityScanner scanner : allScanners) {
            try {
                registry.register(scanner);
            } catch (Exception e) {
                logger.log(Level.WARNING,
                        String.format("Failed to register async scanner: %s", scanner.getName()), e);
            }
        }

        logger.info(String.format("Total async scanners discovered: %d", allScanners.size()));
        return allScanners;
    }

    /**
     * Load scanners from classpath using ServiceLoader.
     *
     * @return list of classpath scanners
     */
    private List<AsyncVulnerabilityScanner> loadClasspathScanners() {
        List<AsyncVulnerabilityScanner> scanners = new ArrayList<>();

        try {
            ServiceLoader<AsyncVulnerabilityScanner> serviceLoader =
                    ServiceLoader.load(AsyncVulnerabilityScanner.class, getClass().getClassLoader());

            for (AsyncVulnerabilityScanner scanner : serviceLoader) {
                logger.info(String.format("Discovered classpath async scanner: %s (%s)",
                        scanner.getName(), scanner.getClass().getName()));
                scanners.add(scanner);
            }
        } catch (ServiceConfigurationError e) {
            logger.log(Level.WARNING, "Error loading classpath async scanners", e);
        }

        return scanners;
    }

    /**
     * Load scanners from plugin JAR files.
     *
     * @return list of plugin scanners
     */
    private List<AsyncVulnerabilityScanner> loadPluginScanners() {
        List<AsyncVulnerabilityScanner> scanners = new ArrayList<>();

        File pluginsDir = new File(pluginsDirectory);
        if (!pluginsDir.exists() || !pluginsDir.isDirectory()) {
            logger.warning(String.format("Plugins directory does not exist or is not a directory: %s",
                    pluginsDirectory));
            return scanners;
        }

        File[] jarFiles = pluginsDir.listFiles((dir, name) ->
                name.startsWith(PLUGIN_PREFIX) && name.endsWith(JAR_EXTENSION));

        if (jarFiles == null || jarFiles.length == 0) {
            logger.info("No async scanner plugin JARs found");
            return scanners;
        }

        logger.info(String.format("Found %d async scanner plugin JAR(s)", jarFiles.length));

        for (File jarFile : jarFiles) {
            try {
                List<AsyncVulnerabilityScanner> pluginScanners = loadScannersFromJar(jarFile);
                scanners.addAll(pluginScanners);
            } catch (Exception e) {
                logger.log(Level.WARNING,
                        String.format("Failed to load async scanners from %s", jarFile.getName()), e);
            }
        }

        return scanners;
    }

    /**
     * Load scanners from a single JAR file.
     *
     * @param jarFile the JAR file to load
     * @return list of scanners from this JAR
     * @throws Exception if loading fails
     */
    private List<AsyncVulnerabilityScanner> loadScannersFromJar(File jarFile) throws Exception {
        List<AsyncVulnerabilityScanner> scanners = new ArrayList<>();

        logger.info(String.format("Loading async scanners from: %s", jarFile.getName()));

        // Create isolated class loader for this plugin
        URL jarUrl = jarFile.toURI().toURL();
        URLClassLoader classLoader = new URLClassLoader(
                new URL[]{jarUrl},
                getClass().getClassLoader()
        );
        classLoaders.add(classLoader);

        // Use ServiceLoader to discover AsyncVulnerabilityScanner implementations
        ServiceLoader<AsyncVulnerabilityScanner> serviceLoader =
                ServiceLoader.load(AsyncVulnerabilityScanner.class, classLoader);

        int count = 0;
        for (AsyncVulnerabilityScanner scanner : serviceLoader) {
            logger.info(String.format("  Discovered: %s (%s) from %s",
                    scanner.getName(),
                    scanner.getClass().getName(),
                    jarFile.getName()));
            scanners.add(scanner);
            count++;
        }

        if (count == 0) {
            logger.warning(String.format("No AsyncVulnerabilityScanner implementations found in %s",
                    jarFile.getName()));
        }

        return scanners;
    }

    /**
     * Close all plugin class loaders and release resources.
     */
    public void close() {
        logger.info("Closing async scanner plugin class loaders");

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
