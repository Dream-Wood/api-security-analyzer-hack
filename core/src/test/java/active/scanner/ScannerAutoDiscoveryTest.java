package active.scanner;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ScannerAutoDiscovery.
 */
class ScannerAutoDiscoveryTest {

    @Test
    void testDiscoverScanners() {
        List<VulnerabilityScanner> scanners = ScannerAutoDiscovery.discoverScanners();

        assertNotNull(scanners);
        assertFalse(scanners.isEmpty(), "Should discover at least one scanner");

        // Verify all discovered scanners have required metadata
        for (VulnerabilityScanner scanner : scanners) {
            assertNotNull(scanner.getId(), "Scanner ID should not be null");
            assertNotNull(scanner.getName(), "Scanner name should not be null");
            assertNotNull(scanner.getDescription(), "Scanner description should not be null");
            assertNotNull(scanner.getDetectedVulnerabilities(),
                "Detected vulnerabilities should not be null");
            assertFalse(scanner.getDetectedVulnerabilities().isEmpty(),
                "Scanner should detect at least one vulnerability type");

            System.out.println("Discovered: " + scanner.getName() + " (ID: " + scanner.getId() + ")");
        }
    }

    @Test
    void testDiscoverAndRegister() {
        ScannerRegistry registry = new ScannerRegistry();

        int registered = ScannerAutoDiscovery.discoverAndRegister(registry);

        assertTrue(registered > 0, "Should register at least one scanner");
        assertEquals(registered, registry.getRegisteredScannerCount());

        // Verify all scanners are enabled by default
        List<VulnerabilityScanner> enabledScanners = registry.getEnabledScanners();
        assertEquals(registered, enabledScanners.size(),
            "All registered scanners should be enabled by default");
    }

    @Test
    void testIsConfigured() {
        boolean configured = ScannerAutoDiscovery.isConfigured();

        assertTrue(configured,
            "Scanner auto-discovery should be configured (META-INF/services file exists)");
    }

    @Test
    void testDiscoverSpecificScanners() {
        List<VulnerabilityScanner> scanners = ScannerAutoDiscovery.discoverScanners();

        // Verify we have the expected scanners
        boolean hasBolaScanner = scanners.stream()
            .anyMatch(s -> s.getId().equals("bola-scanner"));
        boolean hasBrokenAuthScanner = scanners.stream()
            .anyMatch(s -> s.getId().equals("broken-authentication-scanner"));

        assertTrue(hasBolaScanner, "Should discover BolaScanner");
        assertTrue(hasBrokenAuthScanner, "Should discover BrokenAuthenticationScanner");

        // Print all discovered scanner IDs for debugging
        System.out.println("Discovered scanner IDs:");
        scanners.forEach(s -> System.out.println("  - " + s.getId()));
    }

    @Test
    void testDoubleRegistrationPrevention() {
        ScannerRegistry registry = new ScannerRegistry();

        int firstRegistration = ScannerAutoDiscovery.discoverAndRegister(registry);
        assertTrue(firstRegistration > 0);

        // Try to register again - should handle duplicates gracefully
        int secondRegistration = ScannerAutoDiscovery.discoverAndRegister(registry);

        // Second registration should not increase the count
        assertEquals(firstRegistration, registry.getRegisteredScannerCount(),
            "Double registration should not duplicate scanners");
    }
}
