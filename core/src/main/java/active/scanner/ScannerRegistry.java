package active.scanner;

import active.model.VulnerabilityReport;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Registry for managing vulnerability scanner plugins.
 * Scanners can be registered, discovered, and retrieved by various criteria.
 */
public final class ScannerRegistry {
    private static final Logger logger = Logger.getLogger(ScannerRegistry.class.getName());

    private final Map<String, VulnerabilityScanner> scanners = new ConcurrentHashMap<>();

    /**
     * Register a vulnerability scanner.
     *
     * @param scanner the scanner to register
     * @throws IllegalArgumentException if a scanner with the same ID is already registered
     */
    public void register(VulnerabilityScanner scanner) {
        Objects.requireNonNull(scanner, "scanner cannot be null");

        String id = scanner.getId();
        if (scanners.containsKey(id)) {
            throw new IllegalArgumentException(
                "Scanner with ID '" + id + "' is already registered"
            );
        }

        scanners.put(id, scanner);
        logger.info("Registered scanner: " + scanner.getName() + " (ID: " + id + ")");
    }

    /**
     * Unregister a vulnerability scanner.
     *
     * @param scannerId the ID of the scanner to unregister
     * @return true if the scanner was unregistered, false if not found
     */
    public boolean unregister(String scannerId) {
        VulnerabilityScanner removed = scanners.remove(scannerId);
        if (removed != null) {
            logger.info("Unregistered scanner: " + removed.getName() + " (ID: " + scannerId + ")");
            return true;
        }
        return false;
    }

    /**
     * Get a scanner by its ID.
     *
     * @param scannerId the scanner ID
     * @return the scanner, or empty if not found
     */
    public Optional<VulnerabilityScanner> getScanner(String scannerId) {
        return Optional.ofNullable(scanners.get(scannerId));
    }

    /**
     * Get all registered scanners.
     *
     * @return unmodifiable collection of all scanners
     */
    public Collection<VulnerabilityScanner> getAllScanners() {
        return Collections.unmodifiableCollection(scanners.values());
    }

    /**
     * Get all enabled scanners.
     *
     * @return list of enabled scanners
     */
    public List<VulnerabilityScanner> getEnabledScanners() {
        return scanners.values().stream()
            .filter(s -> s.getConfig().isEnabled())
            .collect(Collectors.toList());
    }

    /**
     * Get scanners that can detect a specific vulnerability type.
     *
     * @param vulnerabilityType the vulnerability type
     * @return list of scanners that can detect this type
     */
    public List<VulnerabilityScanner> getScannersByVulnerabilityType(
        VulnerabilityReport.VulnerabilityType vulnerabilityType
    ) {
        return scanners.values().stream()
            .filter(s -> s.getDetectedVulnerabilities().contains(vulnerabilityType))
            .collect(Collectors.toList());
    }

    /**
     * Check if any scanners are registered.
     *
     * @return true if at least one scanner is registered
     */
    public boolean hasRegisteredScanners() {
        return !scanners.isEmpty();
    }

    /**
     * Get the number of registered scanners.
     *
     * @return the number of registered scanners
     */
    public int getRegisteredScannerCount() {
        return scanners.size();
    }

    /**
     * Clear all registered scanners.
     */
    public void clear() {
        logger.info("Clearing all registered scanners");
        scanners.clear();
    }

    /**
     * Get information about all registered scanners.
     *
     * @return map of scanner ID to scanner information
     */
    public Map<String, ScannerInfo> getScannerInfo() {
        return scanners.entrySet().stream()
            .collect(Collectors.toMap(
                Map.Entry::getKey,
                e -> new ScannerInfo(
                    e.getValue().getId(),
                    e.getValue().getName(),
                    e.getValue().getDescription(),
                    e.getValue().getDetectedVulnerabilities(),
                    e.getValue().getConfig().isEnabled()
                )
            ));
    }

    /**
     * Information about a registered scanner.
     */
    public record ScannerInfo(
        String id,
        String name,
        String description,
        List<VulnerabilityReport.VulnerabilityType> detectedVulnerabilities,
        boolean enabled
    ) {}
}
