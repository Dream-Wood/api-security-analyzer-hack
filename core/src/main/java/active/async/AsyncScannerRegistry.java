package active.async;

import model.AsyncOperationSpec;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Thread-safe registry for managing async vulnerability scanner implementations.
 * Async scanners are loaded as hotswap plugins and registered here for use by AsyncAnalysisEngine.
 *
 * <p><b>Thread Safety:</b> All operations are thread-safe using ConcurrentHashMap.
 *
 * <p><b>Usage Example:</b>
 * <pre>
 * AsyncScannerRegistry registry = AsyncScannerRegistry.getInstance();
 * registry.register(new UnauthorizedSubscriptionScanner());
 * registry.register(new MessageInjectionScanner());
 *
 * List<AsyncVulnerabilityScanner> scanners =
 *     registry.getApplicableScanners(operation, "kafka");
 * </pre>
 */
public class AsyncScannerRegistry {

    private static final Logger logger = Logger.getLogger(AsyncScannerRegistry.class.getName());
    private static final AsyncScannerRegistry INSTANCE = new AsyncScannerRegistry();

    private final Map<String, AsyncVulnerabilityScanner> scanners;
    private final Map<String, Boolean> enabledState;

    private AsyncScannerRegistry() {
        this.scanners = new ConcurrentHashMap<>();
        this.enabledState = new ConcurrentHashMap<>();
    }

    /**
     * Get the singleton instance of the registry.
     *
     * @return the registry instance
     */
    public static AsyncScannerRegistry getInstance() {
        return INSTANCE;
    }

    /**
     * Register an async vulnerability scanner in the registry.
     *
     * <p>If a scanner with the same name already exists, it will be replaced
     * and a warning will be logged.
     *
     * @param scanner the scanner to register
     * @throws IllegalArgumentException if scanner is null or name is invalid
     */
    public void register(AsyncVulnerabilityScanner scanner) {
        if (scanner == null) {
            throw new IllegalArgumentException("Scanner cannot be null");
        }

        String name = scanner.getName();
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Scanner name cannot be null or empty");
        }

        if (scanners.containsKey(name)) {
            logger.warning(String.format(
                    "Async scanner '%s' already registered, replacing with %s",
                    name, scanner.getClass().getName()));
        }

        scanners.put(name, scanner);
        enabledState.put(name, scanner.isEnabledByDefault());

        logger.info(String.format("Registered async scanner: %s (%s) - %s",
                name, scanner.getClass().getName(),
                scanner.isEnabledByDefault() ? "enabled" : "disabled"));
    }

    /**
     * Unregister a scanner from the registry.
     *
     * @param scannerName the scanner name to unregister
     * @return true if a scanner was removed, false if not found
     */
    public boolean unregister(String scannerName) {
        if (scannerName == null) {
            return false;
        }

        AsyncVulnerabilityScanner removed = scanners.remove(scannerName);
        enabledState.remove(scannerName);

        if (removed != null) {
            logger.info(String.format("Unregistered async scanner: %s", scannerName));
            return true;
        }

        return false;
    }

    /**
     * Get a scanner by name.
     *
     * @param scannerName the scanner name
     * @return the scanner, or null if not found
     */
    public AsyncVulnerabilityScanner getScanner(String scannerName) {
        return scanners.get(scannerName);
    }

    /**
     * Get all registered scanners.
     *
     * @return unmodifiable collection of scanners
     */
    public Collection<AsyncVulnerabilityScanner> getAllScanners() {
        return Collections.unmodifiableCollection(scanners.values());
    }

    /**
     * Get all enabled scanners.
     *
     * @return list of enabled scanners
     */
    public List<AsyncVulnerabilityScanner> getEnabledScanners() {
        return scanners.entrySet().stream()
                .filter(entry -> Boolean.TRUE.equals(enabledState.get(entry.getKey())))
                .map(Map.Entry::getValue)
                .collect(Collectors.toList());
    }

    /**
     * Get scanners applicable to a specific operation and protocol.
     *
     * <p>A scanner is applicable if:
     * <ul>
     *   <li>It is enabled</li>
     *   <li>It supports the protocol (or supports all protocols)</li>
     *   <li>Its isApplicable() method returns true for the operation</li>
     * </ul>
     *
     * @param operation the async operation
     * @param protocol  the protocol name
     * @return list of applicable scanners
     */
    public List<AsyncVulnerabilityScanner> getApplicableScanners(
            AsyncOperationSpec operation, String protocol) {

        if (operation == null || protocol == null) {
            return Collections.emptyList();
        }

        String normalizedProtocol = protocol.toLowerCase();

        return getEnabledScanners().stream()
                .filter(scanner -> supportsProtocol(scanner, normalizedProtocol))
                .filter(scanner -> scanner.isApplicable(operation))
                .collect(Collectors.toList());
    }

    /**
     * Check if a scanner supports a specific protocol.
     *
     * @param scanner  the scanner
     * @param protocol the protocol name (lowercase)
     * @return true if scanner supports the protocol
     */
    private boolean supportsProtocol(AsyncVulnerabilityScanner scanner, String protocol) {
        List<String> supportedProtocols = scanner.getSupportedProtocols();

        // Empty list or ["*"] means all protocols
        if (supportedProtocols == null ||
                supportedProtocols.isEmpty() ||
                supportedProtocols.contains("*")) {
            return true;
        }

        return supportedProtocols.stream()
                .map(String::toLowerCase)
                .anyMatch(p -> p.equals(protocol));
    }

    /**
     * Enable a scanner by name.
     *
     * @param scannerName the scanner name
     * @return true if scanner was found and enabled
     */
    public boolean enableScanner(String scannerName) {
        if (scannerName != null && scanners.containsKey(scannerName)) {
            enabledState.put(scannerName, true);
            logger.info(String.format("Enabled async scanner: %s", scannerName));
            return true;
        }
        return false;
    }

    /**
     * Disable a scanner by name.
     *
     * @param scannerName the scanner name
     * @return true if scanner was found and disabled
     */
    public boolean disableScanner(String scannerName) {
        if (scannerName != null && scanners.containsKey(scannerName)) {
            enabledState.put(scannerName, false);
            logger.info(String.format("Disabled async scanner: %s", scannerName));
            return true;
        }
        return false;
    }

    /**
     * Check if a scanner is enabled.
     *
     * @param scannerName the scanner name
     * @return true if enabled
     */
    public boolean isEnabled(String scannerName) {
        return Boolean.TRUE.equals(enabledState.get(scannerName));
    }

    /**
     * Get all registered scanner names.
     *
     * @return unmodifiable set of scanner names
     */
    public Set<String> getScannerNames() {
        return Collections.unmodifiableSet(scanners.keySet());
    }

    /**
     * Get the number of registered scanners.
     *
     * @return scanner count
     */
    public int getScannerCount() {
        return scanners.size();
    }

    /**
     * Clear all registered scanners.
     * Useful for testing or reinitialization.
     */
    public void clear() {
        logger.info("Clearing all async scanners from registry");
        scanners.clear();
        enabledState.clear();
    }

    /**
     * Get a formatted string representation of all registered scanners.
     *
     * @return formatted string with scanner information
     */
    public String getRegistryInfo() {
        if (scanners.isEmpty()) {
            return "No async scanners registered";
        }

        StringBuilder info = new StringBuilder();
        info.append(String.format("Registered Async Scanners (%d):\n", scanners.size()));

        List<String> sortedNames = new ArrayList<>(scanners.keySet());
        Collections.sort(sortedNames);

        for (String name : sortedNames) {
            AsyncVulnerabilityScanner scanner = scanners.get(name);
            boolean enabled = Boolean.TRUE.equals(enabledState.get(name));
            String status = enabled ? "enabled" : "disabled";

            List<String> protocols = scanner.getSupportedProtocols();
            String protocolStr = (protocols == null || protocols.isEmpty() || protocols.contains("*"))
                    ? "all"
                    : String.join(", ", protocols);

            info.append(String.format("  - %s [%s] (protocols: %s) - v%s by %s\n",
                    name,
                    status,
                    protocolStr,
                    scanner.getVersion(),
                    scanner.getAuthor()));
        }

        return info.toString();
    }

    @Override
    public String toString() {
        return String.format("AsyncScannerRegistry{scanners=%d, enabled=%d}",
                scanners.size(), getEnabledScanners().size());
    }
}
