package active.scanner;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;
import java.util.logging.Logger;

/**
 * Auto-discovery mechanism for vulnerability scanners using Java SPI (ServiceLoader).
 *
 * <p>Scanners are automatically discovered and loaded from the classpath using the
 * Java ServiceLoader mechanism. To register a scanner:
 * <ol>
 *   <li>Implement {@link VulnerabilityScanner} interface</li>
 *   <li>Add the fully qualified class name to
 *       {@code META-INF/services/active.scanner.VulnerabilityScanner}</li>
 * </ol>
 *
 * <p>Example META-INF/services file content:
 * <pre>
 * active.scanner.bola.BolaScanner
 * active.scanner.brokenauth.BrokenAuthenticationScanner
 * </pre>
 *
 * <p>This eliminates the need for manual registration in code.
 */
public final class ScannerAutoDiscovery {
    private static final Logger logger = Logger.getLogger(ScannerAutoDiscovery.class.getName());

    private ScannerAutoDiscovery() {
        // Utility class
    }

    /**
     * Discover and load all vulnerability scanners from the classpath.
     * Uses Java ServiceLoader to find implementations of VulnerabilityScanner.
     *
     * @return list of discovered scanner instances
     */
    public static List<VulnerabilityScanner> discoverScanners() {
        List<VulnerabilityScanner> scanners = new ArrayList<>();

        logger.info("Starting auto-discovery of vulnerability scanners...");

        ServiceLoader<VulnerabilityScanner> serviceLoader =
            ServiceLoader.load(VulnerabilityScanner.class);

        int count = 0;
        for (VulnerabilityScanner scanner : serviceLoader) {
            try {
                scanners.add(scanner);
                count++;
                logger.info("Discovered scanner: " + scanner.getName() +
                           " (ID: " + scanner.getId() + ")");
            } catch (Exception e) {
                logger.warning("Failed to load scanner: " + e.getMessage());
            }
        }

        logger.info("Auto-discovery completed. Found " + count + " scanner(s)");

        return scanners;
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
