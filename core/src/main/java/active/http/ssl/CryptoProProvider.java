package active.http.ssl;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Utility class for managing CryptoPro security providers.
 *
 * <p>This class handles registration and verification of CryptoPro JCSP providers
 * required for GOST cryptography operations.
 *
 * <p><b>Required CryptoPro libraries:</b>
 * <ul>
 *   <li>JCP (Java Crypto Provider) - ru.CryptoPro.JCP.JCP</li>
 *   <li>SSL Provider - ru.CryptoPro.ssl.Provider</li>
 *   <li>Crypto Provider - ru.CryptoPro.Crypto.CryptoProvider</li>
 *   <li>RevCheck (optional) - ru.CryptoPro.reprov.RevCheck</li>
 * </ul>
 *
 * <p><b>Usage:</b>
 * <pre>
 * // Initialize all required providers
 * CryptoProProvider.initialize();
 *
 * // Check if providers are available
 * if (CryptoProProvider.isAvailable()) {
 *     // Use GOST cryptography
 * }
 * </pre>
 */
public final class CryptoProProvider {
    private static final Logger logger = Logger.getLogger(CryptoProProvider.class.getName());

    private static volatile boolean initialized = false;

    /**
     * CryptoPro provider types.
     */
    public enum ProviderType {
        /** Main Java Crypto Provider */
        JCP("ru.CryptoPro.JCP.JCP", true),
        JCSP("ru.CryptoPro.JCSP.JCSP", true),

        /** SSL/TLS Provider for GOST protocols */
        SSL("ru.CryptoPro.ssl.Provider", true),

        /** Additional Crypto Operations Provider */
        CRYPTO("ru.CryptoPro.Crypto.CryptoProvider", true),

        /** Certificate Revocation Check Provider (optional) */
        REVCHECK("ru.CryptoPro.reprov.RevCheck", false);

        private final String className;
        private final boolean required;

        ProviderType(String className, boolean required) {
            this.className = className;
            this.required = required;
        }

        public String getClassName() {
            return className;
        }

        public boolean isRequired() {
            return required;
        }
    }

    // Prevent instantiation
    private CryptoProProvider() {
    }

    /**
     * Initialize all CryptoPro security providers.
     * This method is idempotent and can be called multiple times safely.
     *
     * @throws RuntimeException if required providers cannot be loaded
     */
    public static synchronized void initialize() {
        if (initialized) {
            logger.fine("CryptoPro providers already initialized");
            return;
        }

        logger.info("Initializing CryptoPro security providers...");

        for (ProviderType type : ProviderType.values()) {
            try {
                registerProvider(type);
            } catch (ProviderRegistrationException e) {
                if (type.isRequired()) {
                    throw new RuntimeException(
                        "Failed to initialize required CryptoPro provider: " + type.name() + ". " +
                        "Ensure CryptoPro JCP libraries are properly installed and licensed.",
                        e
                    );
                } else {
                    logger.fine("Optional provider not available: " + type.name());
                }
            }
        }

        initialized = true;
        logger.info("CryptoPro providers initialized successfully");

        // Log registered providers for debugging
        if (logger.isLoggable(Level.FINE)) {
            logRegisteredProviders();
        }
    }

    /**
     * Register a specific CryptoPro provider.
     *
     * @param type the provider type to register
     * @throws ProviderRegistrationException if provider cannot be registered
     */
    public static void registerProvider(ProviderType type) throws ProviderRegistrationException {
        try {
            Class<?> providerClass = Class.forName(type.getClassName());
            Provider provider = (Provider) providerClass.getDeclaredConstructor().newInstance();

            // Check if already registered
            if (Security.getProvider(provider.getName()) != null) {
                logger.fine("Provider already registered: " + provider.getName() +
                           " (" + type.getClassName() + ")");
                return;
            }

            // Add provider
            int position = Security.addProvider(provider);

            if (position == -1) {
                throw new ProviderRegistrationException(
                    "Failed to add provider (already registered with different instance?): " +
                    type.getClassName()
                );
            }

            logger.info("Registered CryptoPro provider: " + provider.getName() +
                       " at position " + position +
                       " (" + type.getClassName() + ")");

        } catch (ClassNotFoundException e) {
            throw new ProviderRegistrationException(
                "Provider class not found: " + type.getClassName() + ". " +
                "Ensure CryptoPro JCP libraries are in classpath.",
                e
            );
        } catch (Exception e) {
            throw new ProviderRegistrationException(
                "Failed to instantiate provider: " + type.getClassName(),
                e
            );
        }
    }

    /**
     * Check if CryptoPro providers are available.
     * This checks if the main JCP provider class can be loaded.
     *
     * @return true if CryptoPro is available, false otherwise
     */
    public static boolean isAvailable() {
        try {
            Class.forName(ProviderType.JCP.getClassName());
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    /**
     * Check if a specific provider type is available.
     *
     * @param type the provider type to check
     * @return true if available, false otherwise
     */
    public static boolean isProviderAvailable(ProviderType type) {
        try {
            Class.forName(type.getClassName());
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    /**
     * Check if a specific provider is registered.
     *
     * @param type the provider type to check
     * @return true if registered, false otherwise
     */
    public static boolean isProviderRegistered(ProviderType type) {
        try {
            Class<?> providerClass = Class.forName(type.getClassName());
            Provider provider = (Provider) providerClass.getDeclaredConstructor().newInstance();
            return Security.getProvider(provider.getName()) != null;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get all registered CryptoPro providers.
     *
     * @return list of registered CryptoPro provider names
     */
    public static List<String> getRegisteredProviders() {
        return Arrays.stream(ProviderType.values())
            .filter(CryptoProProvider::isProviderRegistered)
            .map(type -> {
                try {
                    Class<?> providerClass = Class.forName(type.getClassName());
                    Provider provider = (Provider) providerClass.getDeclaredConstructor().newInstance();
                    return provider.getName();
                } catch (Exception e) {
                    return null;
                }
            })
            .filter(name -> name != null)
            .collect(Collectors.toList());
    }

    /**
     * Check if CryptoPro providers have been initialized.
     *
     * @return true if initialized, false otherwise
     */
    public static boolean isInitialized() {
        return initialized;
    }

    /**
     * Log all registered security providers for debugging.
     */
    private static void logRegisteredProviders() {
        Provider[] providers = Security.getProviders();
        logger.fine("Registered security providers (" + providers.length + "):");

        for (int i = 0; i < providers.length; i++) {
            Provider p = providers[i];
            logger.fine(String.format("  [%d] %s %s (%s)",
                i + 1,
                p.getName(),
                p.getVersionStr(),
                p.getClass().getName()
            ));
        }
    }

    /**
     * Exception thrown when provider registration fails.
     */
    public static class ProviderRegistrationException extends Exception {
        public ProviderRegistrationException(String message) {
            super(message);
        }

        public ProviderRegistrationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
