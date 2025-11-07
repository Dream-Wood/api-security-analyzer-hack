package active.scanner;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Plugin loader for dynamically loading vulnerability scanner plugins from JAR files.
 *
 * <p>This class enables hot-swappable scanner plugins similar to Minecraft mods:
 * <ul>
 *   <li>Drop scanner JAR files into the plugins/ directory</li>
 *   <li>Restart the application</li>
 *   <li>Scanners are automatically discovered and loaded</li>
 * </ul>
 *
 * <p>Each plugin JAR should contain:
 * <ul>
 *   <li>Scanner implementation classes</li>
 *   <li>META-INF/services/active.scanner.VulnerabilityScanner file listing scanner classes</li>
 * </ul>
 *
 * <p>Plugin isolation:
 * Each plugin JAR is loaded with its own URLClassLoader to provide isolation and
 * enable independent versioning of dependencies.
 *
 * <p>Example directory structure:
 * <pre>
 * plugins/
 *   scanner-bola-1.0.0.jar
 *   scanner-sqlinjection-1.0.0.jar
 *   scanner-custom-2.1.0.jar
 * </pre>
 */
public final class PluginLoader {
    private static final Logger logger = Logger.getLogger(PluginLoader.class.getName());

    private static final String DEFAULT_PLUGIN_DIR = "plugins";
    private static final String PLUGIN_DIR_PROPERTY = "scanner.plugin.dir";

    private final Path pluginDirectory;
    private final List<PluginClassLoader> pluginClassLoaders = new ArrayList<>();

    /**
     * Create a plugin loader with the default plugin directory.
     * The directory can be overridden with system property: scanner.plugin.dir
     */
    public PluginLoader() {
        String pluginDir = System.getProperty(PLUGIN_DIR_PROPERTY, DEFAULT_PLUGIN_DIR);
        this.pluginDirectory = Paths.get(pluginDir);
    }

    /**
     * Create a plugin loader with a custom plugin directory.
     *
     * @param pluginDirectory the directory to load plugins from
     */
    public PluginLoader(Path pluginDirectory) {
        this.pluginDirectory = Objects.requireNonNull(pluginDirectory, "pluginDirectory cannot be null");
    }

    /**
     * Load all scanner plugins from the plugin directory.
     *
     * @return list of loaded scanner instances
     */
    public List<VulnerabilityScanner> loadPlugins() {
        List<VulnerabilityScanner> scanners = new ArrayList<>();

        if (!Files.exists(pluginDirectory)) {
            logger.info("Plugin directory does not exist: " + pluginDirectory +
                       " - no plugins will be loaded. Create this directory to enable plugins.");
            return scanners;
        }

        if (!Files.isDirectory(pluginDirectory)) {
            logger.warning("Plugin path is not a directory: " + pluginDirectory);
            return scanners;
        }

        logger.info("Loading scanner plugins from: " + pluginDirectory.toAbsolutePath());

        List<Path> jarFiles = findJarFiles();
        if (jarFiles.isEmpty()) {
            logger.info("No plugin JAR files found in: " + pluginDirectory);
            return scanners;
        }

        logger.info("Found " + jarFiles.size() + " plugin JAR file(s)");

        for (Path jarFile : jarFiles) {
            try {
                List<VulnerabilityScanner> pluginScanners = loadPluginFromJar(jarFile);
                scanners.addAll(pluginScanners);
            } catch (Exception e) {
                logger.warning("Failed to load plugin from " + jarFile.getFileName() + ": " + e.getMessage());
            }
        }

        logger.info("Successfully loaded " + scanners.size() + " scanner(s) from plugins");

        return scanners;
    }

    /**
     * Load scanners from a specific JAR file.
     *
     * @param jarFile the JAR file to load
     * @return list of scanner instances from this JAR
     * @throws IOException if the JAR cannot be read
     */
    private List<VulnerabilityScanner> loadPluginFromJar(Path jarFile) throws IOException {
        List<VulnerabilityScanner> scanners = new ArrayList<>();

        logger.fine("Loading plugin: " + jarFile.getFileName());

        // Create a new ClassLoader for this plugin JAR
        URL jarUrl = jarFile.toUri().toURL();
        PluginClassLoader classLoader = new PluginClassLoader(
            new URL[]{jarUrl},
            getClass().getClassLoader()
        );
        pluginClassLoaders.add(classLoader);

        // Use ServiceLoader with the plugin's ClassLoader
        ServiceLoader<VulnerabilityScanner> serviceLoader =
            ServiceLoader.load(VulnerabilityScanner.class, classLoader);

        int count = 0;
        for (VulnerabilityScanner scanner : serviceLoader) {
            scanners.add(scanner);
            count++;
            logger.info("  Loaded scanner: " + scanner.getName() +
                       " (ID: " + scanner.getId() + ") from " + jarFile.getFileName());
        }

        if (count == 0) {
            logger.fine("  No scanners found in " + jarFile.getFileName() +
                       " (check META-INF/services/active.scanner.VulnerabilityScanner)");
        }

        return scanners;
    }

    /**
     * Find all JAR files in the plugin directory.
     *
     * @return list of JAR file paths
     */
    private List<Path> findJarFiles() {
        try (Stream<Path> files = Files.list(pluginDirectory)) {
            return files
                .filter(Files::isRegularFile)
                .filter(path -> path.toString().toLowerCase().endsWith(".jar"))
                .sorted()
                .collect(Collectors.toList());
        } catch (IOException e) {
            logger.warning("Failed to list files in plugin directory: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Get the plugin directory path.
     *
     * @return the plugin directory
     */
    public Path getPluginDirectory() {
        return pluginDirectory;
    }

    /**
     * Close all plugin class loaders and release resources.
     * Should be called when the application shuts down.
     */
    public void close() {
        for (PluginClassLoader classLoader : pluginClassLoaders) {
            try {
                classLoader.close();
            } catch (IOException e) {
                logger.warning("Failed to close plugin class loader: " + e.getMessage());
            }
        }
        pluginClassLoaders.clear();
    }

    /**
     * Custom ClassLoader for plugin isolation.
     * Allows each plugin to have its own dependencies without conflicts.
     */
    private static class PluginClassLoader extends URLClassLoader {
        public PluginClassLoader(URL[] urls, ClassLoader parent) {
            super(urls, parent);
        }

        @Override
        public String toString() {
            URL[] urls = getURLs();
            if (urls.length > 0) {
                File file = new File(urls[0].getFile());
                return "PluginClassLoader[" + file.getName() + "]";
            }
            return "PluginClassLoader[]";
        }
    }
}
