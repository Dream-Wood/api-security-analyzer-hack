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
        /** Java Crypto Service Provider (новая версия) */
        JCSP("ru.CryptoPro.JCSP.JCSP", false),

        /** Java Crypto Provider (старая версия) */
        JCP("ru.CryptoPro.JCP.JCP", false),

        /** SSPI SSL Provider (предпочтительный для Windows) */
        SSPISSL("ru.CryptoPro.sspiSSL.SSPISSL", false),

        /** SSL/TLS Provider для протоколов ГОСТ */
        SSL("ru.CryptoPro.ssl.Provider", true),

        /** Провайдер дополнительных криптографических операций */
        CRYPTO("ru.CryptoPro.Crypto.CryptoProvider", false),

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
     * <p>Порядок загрузки провайдеров критичен:
     * <ol>
     *   <li>Сначала пытаемся загрузить JCSP (новая версия)</li>
     *   <li>Если JCSP есть: загружаем SSPISSL (или SSL если SSPISSL недоступен)</li>
     *   <li>Если JCSP нет: загружаем JCP + Crypto + SSL (старая версия)</li>
     *   <li>В конце загружаем RevCheck (опционально)</li>
     * </ol>
     *
     * @throws RuntimeException если необходимые провайдеры не могут быть загружены
     */
    public static synchronized void initialize() {
        if (initialized) {
            logger.fine("CryptoPro providers already initialized");
            return;
        }

        logger.info("Initializing CryptoPro security providers...");

        // Установить системные свойства для CryptoPro
        configureSystemProperties();

        // Загрузить провайдеры в правильном порядке
        boolean hasSSLProvider = false;

        // Шаг 1: Попробовать загрузить JCSP (новая версия)
        try {
            registerProvider(ProviderType.JCSP);
            logger.info("Using JCSP (new version) provider");

            // Если JCSP успешно загружен, пробуем SSPISSL или SSL
            try {
                registerProvider(ProviderType.SSPISSL);
                hasSSLProvider = true;
                logger.info("Using SSPISSL provider (Windows optimized)");
            } catch (ProviderRegistrationException e) {
                logger.fine("SSPISSL not available, trying SSL provider");
                try {
                    registerProvider(ProviderType.SSL);
                    hasSSLProvider = true;
                    logger.info("Using SSL provider");
                } catch (ProviderRegistrationException ex) {
                    throw new RuntimeException(
                        "Failed to load SSL provider. Ensure CryptoPro SSL libraries are installed.",
                        ex
                    );
                }
            }

        } catch (ProviderRegistrationException e) {
            logger.info("JCSP not available, trying JCP (old version)");

            // Шаг 2: Если JCSP недоступен, используем старую версию (JCP)
            try {
                registerProvider(ProviderType.JCP);
                logger.info("Using JCP (old version) provider");

                // Загрузить Crypto provider
                try {
                    registerProvider(ProviderType.CRYPTO);
                } catch (ProviderRegistrationException ex) {
                    logger.warning("Crypto provider not available: " + ex.getMessage());
                }

                // Загрузить SSL provider
                try {
                    registerProvider(ProviderType.SSL);
                    hasSSLProvider = true;
                    logger.info("Using SSL provider");
                } catch (ProviderRegistrationException ex) {
                    throw new RuntimeException(
                        "Failed to load SSL provider. Ensure CryptoPro SSL libraries are installed.",
                        ex
                    );
                }

            } catch (ProviderRegistrationException ex) {
                throw new RuntimeException(
                    "Failed to initialize CryptoPro providers. " +
                    "Neither JCSP nor JCP could be loaded. " +
                    "Ensure CryptoPro JCP/JCSP libraries are properly installed and licensed.",
                    ex
                );
            }
        }

        // Шаг 3: Загрузить RevCheck (опционально)
        try {
            registerProvider(ProviderType.REVCHECK);
            logger.info("RevCheck provider loaded (certificate revocation checking enabled)");
        } catch (ProviderRegistrationException e) {
            logger.fine("RevCheck provider not available (certificate revocation checking disabled)");
        }

        if (!hasSSLProvider) {
            throw new RuntimeException(
                "No SSL provider was loaded. Cannot create GOST TLS connections. " +
                "Ensure CryptoPro SSL libraries are properly installed."
            );
        }

        initialized = true;
        logger.info("CryptoPro providers initialized successfully");

        // Log registered providers for debugging
        if (logger.isLoggable(Level.FINE)) {
            logRegisteredProviders();
        }
    }

    /**
     * Настроить системные свойства для CryptoPro.
     */
    private static void configureSystemProperties() {
        // Certificate revocation checking properties
        System.setProperty("com.ibm.security.enableCRLDP", "true");
        System.setProperty("com.sun.security.enableCRLDP", "true");
        System.setProperty("com.sun.security.enableAIAcaIssuers", "true");
        System.setProperty("ru.CryptoPro.reprov.enableAIAcaIssuers", "true");
        System.setProperty("java.util.prefs.syncInterval", "99999");

        // Disable hostname verification in CryptoPro SSL (для совместимости)
        System.setProperty("ru.CryptoPro.ssl.checkHostname", "false");
        System.setProperty("com.sun.net.ssl.checkRevocation", "false");

        // Enable detailed logging for troubleshooting
        if (logger.isLoggable(Level.FINE)) {
            java.util.logging.Logger.getLogger("ru.CryptoPro.ssl.SSLLogger").setLevel(java.util.logging.Level.ALL);
            java.util.logging.Logger.getLogger("ru.CryptoPro.JCSP.JCSPLogger").setLevel(java.util.logging.Level.ALL);
        }

        logger.fine("CryptoPro system properties configured");
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
