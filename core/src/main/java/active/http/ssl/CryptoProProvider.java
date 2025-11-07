package active.http.ssl;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Утилитарный класс для управления провайдерами безопасности CryptoPro.
 *
 * <p>Этот класс обрабатывает регистрацию и проверку провайдеров CryptoPro JCSP,
 * необходимых для операций криптографии ГОСТ.
 *
 * <p><b>Необходимые библиотеки CryptoPro:</b>
 * <ul>
 *   <li>JCP (Java Crypto Provider) - ru.CryptoPro.JCP.JCP</li>
 *   <li>SSL Provider - ru.CryptoPro.ssl.Provider</li>
 *   <li>Crypto Provider - ru.CryptoPro.Crypto.CryptoProvider</li>
 *   <li>RevCheck (опционально) - ru.CryptoPro.reprov.RevCheck</li>
 * </ul>
 *
 * <p><b>Использование:</b>
 * <pre>
 * // Инициализировать все необходимые провайдеры
 * CryptoProProvider.initialize();
 *
 * // Проверить доступность провайдеров
 * if (CryptoProProvider.isAvailable()) {
 *     // Использовать ГОСТ криптографию
 * }
 * </pre>
 */
public final class CryptoProProvider {
    private static final Logger logger = Logger.getLogger(CryptoProProvider.class.getName());

    private static volatile boolean initialized = false;

    /**
     * Типы провайдеров CryptoPro.
     */
    public enum ProviderType {
        /** Основной Java Crypto Provider */
        JCP("ru.CryptoPro.JCP.JCP", true),
        JCSP("ru.CryptoPro.JCSP.JCSP", true),

        /** SSL/TLS Provider для протоколов ГОСТ */
        SSL("ru.CryptoPro.ssl.Provider", true),

        /** Провайдер дополнительных криптографических операций */
        CRYPTO("ru.CryptoPro.Crypto.CryptoProvider", true),

        /** Провайдер проверки отзыва сертификатов (опционально) */
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
     * Инициализировать все провайдеры безопасности CryptoPro.
     * Этот метод идемпотентен и может быть вызван несколько раз безопасно.
     *
     * @throws RuntimeException если необходимые провайдеры не могут быть загружены
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
     * Зарегистрировать конкретный провайдер CryptoPro.
     *
     * @param type тип провайдера для регистрации
     * @throws ProviderRegistrationException если провайдер не может быть зарегистрирован
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
     * Проверить, доступны ли провайдеры CryptoPro.
     * Проверяет, может ли быть загружен основной класс провайдера JCP.
     *
     * @return true если CryptoPro доступен, false в противном случае
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
     * Проверить, доступен ли конкретный тип провайдера.
     *
     * @param type тип провайдера для проверки
     * @return true если доступен, false в противном случае
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
     * Проверить, зарегистрирован ли конкретный провайдер.
     *
     * @param type тип провайдера для проверки
     * @return true если зарегистрирован, false в противном случае
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
     * Получить все зарегистрированные провайдеры CryptoPro.
     *
     * @return список имен зарегистрированных провайдеров CryptoPro
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
     * Проверить, были ли инициализированы провайдеры CryptoPro.
     *
     * @return true если инициализированы, false в противном случае
     */
    public static boolean isInitialized() {
        return initialized;
    }

    /**
     * Логировать все зарегистрированные провайдеры безопасности для отладки.
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
     * Исключение, выбрасываемое при ошибке регистрации провайдера.
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
