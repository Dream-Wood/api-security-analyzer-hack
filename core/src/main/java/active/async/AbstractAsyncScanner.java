package active.async;

import active.protocol.ProtocolClient;
import active.protocol.ProtocolException;
import active.scanner.ScanContext;
import model.AsyncOperationSpec;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Abstract base class for async vulnerability scanners providing common functionality.
 * Extends AsyncVulnerabilityScanner with helpful utilities for scanning async operations.
 *
 * <p>Provides:
 * <ul>
 *   <li>Exception handling and logging</li>
 *   <li>Timing measurements</li>
 *   <li>Request counting</li>
 *   <li>Common helper methods</li>
 * </ul>
 *
 * <p><b>Usage:</b>
 * <pre>
 * public class MyAsyncScanner extends AbstractAsyncScanner {
 *     protected AsyncScanResult performScan(AsyncOperationSpec operation,
 *                                           ProtocolClient client,
 *                                           ScanContext context) {
 *         // Implement scanning logic
 *         return AsyncScanResult.builder()
 *             .scannerName(getName())
 *             .operation(operation)
 *             .build();
 *     }
 *
 *     public boolean isApplicable(AsyncOperationSpec operation) {
 *         return true; // Define applicability
 *     }
 * }
 * </pre>
 */
public abstract class AbstractAsyncScanner implements AsyncVulnerabilityScanner {

    protected final Logger logger;
    private final String scannerName;
    private int requestCount;

    /**
     * Create an abstract async scanner.
     *
     * @param scannerName the name of this scanner
     */
    protected AbstractAsyncScanner(String scannerName) {
        this.scannerName = scannerName;
        this.logger = Logger.getLogger(getClass().getName());
        this.requestCount = 0;
    }

    @Override
    public String getName() {
        return scannerName;
    }

    @Override
    public final AsyncScanResult scan(AsyncOperationSpec operation,
                                     ProtocolClient client,
                                     ScanContext context) {
        long startTime = System.currentTimeMillis();
        requestCount = 0;

        try {
            logger.fine(String.format("Starting scan: %s on %s/%s",
                    scannerName, operation.getChannelName(), operation.getOperationType()));

            // Perform the actual scan
            AsyncScanResult result = performScan(operation, client, context);

            long duration = System.currentTimeMillis() - startTime;
            logger.fine(String.format("Completed scan: %s (duration=%dms, requests=%d, vulnerabilities=%d)",
                    scannerName, duration, requestCount, result.getVulnerabilityCount()));

            return result;

        } catch (ProtocolException e) {
            long duration = System.currentTimeMillis() - startTime;
            logger.log(Level.WARNING,
                    String.format("Protocol error in %s: %s", scannerName, e.getMessage()), e);

            return AsyncScanResult.builder()
                    .scannerName(scannerName)
                    .operation(operation)
                    .success(false)
                    .errorMessage("Protocol error: " + e.getMessage())
                    .durationMs(duration)
                    .requestCount(requestCount)
                    .build();

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            logger.log(Level.SEVERE,
                    String.format("Unexpected error in %s: %s", scannerName, e.getMessage()), e);

            return AsyncScanResult.builder()
                    .scannerName(scannerName)
                    .operation(operation)
                    .success(false)
                    .errorMessage("Unexpected error: " + e.getMessage())
                    .durationMs(duration)
                    .requestCount(requestCount)
                    .build();
        }
    }

    /**
     * Perform the actual scanning logic.
     * Subclasses must implement this method with their specific vulnerability checks.
     *
     * @param operation the async operation to scan
     * @param client    the protocol client for communication
     * @param context   scan context with settings
     * @return scan result with findings
     * @throws ProtocolException if protocol communication fails
     */
    protected abstract AsyncScanResult performScan(AsyncOperationSpec operation,
                                                   ProtocolClient client,
                                                   ScanContext context) throws ProtocolException;

    /**
     * Increment the request counter.
     * Should be called by subclasses for each protocol operation.
     */
    protected void incrementRequestCount() {
        requestCount++;
    }

    /**
     * Get the current request count for this scan.
     *
     * @return request count
     */
    protected int getRequestCount() {
        return requestCount;
    }

    /**
     * Apply delay based on scan intensity from context.
     * Uses the same intensity settings as HTTP scanners.
     *
     * @param context scan context with intensity settings
     */
    protected void applyDelay(ScanContext context) {
        if (context != null && context.getScanIntensity() != null) {
            try {
                Thread.sleep(context.getScanIntensity().getRequestDelayMs());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.fine("Delay interrupted");
            }
        }
    }

    /**
     * Check if the scan should stop based on context limits.
     *
     * @param context scan context with limits
     * @return true if should stop scanning
     */
    protected boolean shouldStopScan(ScanContext context) {
        if (context == null) {
            return false;
        }

        int maxRequests = context.getMaxRequestsPerEndpoint();
        if (maxRequests > 0 && requestCount >= maxRequests) {
            logger.fine(String.format("Reached max requests limit: %d", maxRequests));
            return true;
        }

        return false;
    }

    /**
     * Create a result builder pre-filled with scanner and operation info.
     *
     * @param operation the operation being scanned
     * @return result builder
     */
    protected AsyncScanResult.Builder createResultBuilder(AsyncOperationSpec operation) {
        return AsyncScanResult.builder()
                .scannerName(scannerName)
                .operation(operation)
                .requestCount(requestCount);
    }

    /**
     * Log a debug message (convenience method).
     *
     * @param message the message
     */
    protected void debug(String message) {
        logger.fine(message);
    }

    /**
     * Log an info message (convenience method).
     *
     * @param message the message
     */
    protected void info(String message) {
        logger.info(message);
    }

    /**
     * Log a warning message (convenience method).
     *
     * @param message the message
     */
    protected void warning(String message) {
        logger.warning(message);
    }

    @Override
    public String toString() {
        return String.format("%s (version %s)", getName(), getVersion());
    }
}
