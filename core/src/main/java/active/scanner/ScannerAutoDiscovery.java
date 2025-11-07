package active.scanner;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;
import java.util.logging.Logger;

/**
 * Auto-discovery mechanism for vulnerability scanners using Java SPI (ServiceLoader).
 *
 * <p>Scanners are automatically discovered and loaded from two sources:
 * <ol>
 *   <li><b>Built-in scanners:</b> Loaded from the classpath using Java ServiceLoader</li>
 *   <li><b>Plugin scanners:</b> Loaded dynamically from JAR files in the plugins/ directory</li>
 * </ol>
 *
 * <p><b>Built-in scanners</b> (classpath):
 * <ul>
 *   <li>Implement {@link VulnerabilityScanner} interface</li>
 *   <li>Add the fully qualified class name to
 *       {@code META-INF/services/active.scanner.VulnerabilityScanner}</li>
 * </ul>
 *
 * <p><b>Plugin scanners</b> (hot-swappable):
 * <ul>
 *   <li>Package scanner as JAR file with META-INF/services configuration</li>
 *   <li>Drop JAR file into plugins/ directory</li>
 *   <li>Restart application - scanner is automatically loaded</li>
 * </ul>
 *
 * <p>Example META-INF/services file content:
 * <pre>
 * active.scanner.bola.BolaScanner
 * active.scanner.brokenauth.BrokenAuthenticationScanner
 * </pre>
 *
 * <p>This eliminates the need for manual registration in code and enables
 * hot-swappable plugins similar to Minecraft mods.
 */
public final class ScannerAutoDiscovery {
    private static final Logger logger = Logger.getLogger(ScannerAutoDiscovery.class.getName());

    private static PluginLoader pluginLoader;

    private ScannerAutoDiscovery() {
        // Utility class
    }

    /**
     * Discover and load all vulnerability scanners from both classpath and plugins.
     * Uses Java ServiceLoader to find implementations of VulnerabilityScanner.
     *
     * @return list of discovered scanner instances
     */
    public static List<VulnerabilityScanner> discoverScanners() {
        return discoverScanners(true);
    }

    /**
     * Discover and load vulnerability scanners with optional plugin loading.
     *
     * @param loadPlugins if true, also load scanners from plugins/ directory
     * @return list of discovered scanner instances
     */
    public static List<VulnerabilityScanner> discoverScanners(boolean loadPlugins) {
        List<VulnerabilityScanner> scanners = new ArrayList<>();

        logger.info("Starting auto-discovery of vulnerability scanners...");

        // 1. Load built-in scanners from classpath
        List<VulnerabilityScanner> builtInScanners = discoverBuiltInScanners();
        scanners.addAll(builtInScanners);

        // 2. Load plugin scanners from plugins/ directory
        if (loadPlugins) {
            List<VulnerabilityScanner> pluginScanners = discoverPluginScanners();
            scanners.addAll(pluginScanners);
        }

        logger.info("Auto-discovery completed. Found " + scanners.size() + " total scanner(s) " +
                   "(" + builtInScanners.size() + " built-in, " +
                   (scanners.size() - builtInScanners.size()) + " plugin)");

        return scanners;
    }

    /**
     * Discover built-in scanners from the classpath.
     *
     * @return list of built-in scanner instances
     */
    private static List<VulnerabilityScanner> discoverBuiltInScanners() {
        List<VulnerabilityScanner> scanners = new ArrayList<>();

        logger.info("Discovering built-in scanners from classpath...");

        ServiceLoader<VulnerabilityScanner> serviceLoader =
            ServiceLoader.load(VulnerabilityScanner.class);

        int count = 0;
        for (VulnerabilityScanner scanner : serviceLoader) {
            try {
                scanners.add(scanner);
                count++;
                logger.info("  Discovered built-in scanner: " + scanner.getName() +
                           " (ID: " + scanner.getId() + ")");
            } catch (Exception e) {
                logger.warning("  Failed to load built-in scanner: " + e.getMessage());
            }
        }

        logger.info("Found " + count + " built-in scanner(s)");

        return scanners;
    }

    /**
     * Discover plugin scanners from the plugins/ directory.
     *
     * @return list of plugin scanner instances
     */
    private static List<VulnerabilityScanner> discoverPluginScanners() {
        logger.info("Discovering plugin scanners from plugins/ directory...");

        // Create or reuse plugin loader
        if (pluginLoader == null) {
            String pluginDir = System.getProperty("scanner.plugin.dir", "plugins");
            pluginLoader = new PluginLoader(Paths.get(pluginDir));
        }

        List<VulnerabilityScanner> pluginScanners = pluginLoader.loadPlugins();

        logger.info("Found " + pluginScanners.size() + " plugin scanner(s)");

        return pluginScanners;
    }

    /**
     * Discover and register all scanners in the given registry.
     *
     * @param registry the scanner registry to register discovered scanners
     * @return number of scanners registered
     */
    public static int discoverAndRegister(ScannerRegistry registry) {
        List<VulnerabilityScanner> scanners = discoverScanners();

        int registered = 0;
        for (VulnerabilityScanner scanner : scanners) {
            try {
                registry.register(scanner);
                registered++;
            } catch (IllegalArgumentException e) {
                logger.warning("Scanner already registered: " + scanner.getId());
            } catch (Exception e) {
                logger.warning("Failed to register scanner " + scanner.getId() +
                             ": " + e.getMessage());
            }
        }

        return registered;
    }

    /**
     * Check if auto-discovery is configured (META-INF/services file exists).
     *
     * @return true if service configuration is present
     */
    public static boolean isConfigured() {
        ServiceLoader<VulnerabilityScanner> serviceLoader =
            ServiceLoader.load(VulnerabilityScanner.class);
        return serviceLoader.iterator().hasNext();
    }
}
