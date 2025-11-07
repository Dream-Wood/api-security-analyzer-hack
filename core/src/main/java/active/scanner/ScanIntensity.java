package active.scanner;

/**
 * Defines the intensity level for vulnerability scanning.
 * Higher intensity means more requests and deeper testing, but may cause load on production systems.
 */
public enum ScanIntensity {
    /**
     * Minimal scanning - suitable for production environments.
     * - Low request rate (500ms delay between requests)
     * - Reduced test cases
     * - Conservative fuzzing
     */
    LOW(500, 0.3),

    /**
     * Balanced scanning - suitable for staging environments.
     * - Moderate request rate (200ms delay)
     * - Standard test cases
     * - Normal fuzzing
     */
    MEDIUM(200, 0.6),

    /**
     * Thorough scanning - suitable for testing environments.
     * - High request rate (100ms delay)
     * - Extended test cases
     * - Aggressive fuzzing
     */
    HIGH(100, 1.0),

    /**
     * Maximum scanning - suitable for development/security testing only.
     * - Maximum request rate (50ms delay)
     * - All test cases
     * - Maximum fuzzing depth
     * WARNING: May cause significant load on the target system
     */
    AGGRESSIVE(50, 1.5);

    private final int requestDelayMs;
    private final double testMultiplier;

    ScanIntensity(int requestDelayMs, double testMultiplier) {
        this.requestDelayMs = requestDelayMs;
        this.testMultiplier = testMultiplier;
    }

    /**
     * Get the delay in milliseconds between consecutive requests.
     */
    public int getRequestDelayMs() {
        return requestDelayMs;
    }

    /**
     * Get the test case multiplier (how many tests to run compared to baseline).
     */
    public double getTestMultiplier() {
        return testMultiplier;
    }

    /**
     * Parse intensity from string (case-insensitive).
     */
    public static ScanIntensity fromString(String value) {
        if (value == null || value.isEmpty()) {
            return MEDIUM; // Default
        }

        try {
            return valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            // Try matching by number (1-4)
            return switch (value) {
                case "1" -> LOW;
                case "2" -> MEDIUM;
                case "3" -> HIGH;
                case "4" -> AGGRESSIVE;
                default -> MEDIUM;
            };
        }
    }

    @Override
    public String toString() {
        return name().toLowerCase();
    }
}
