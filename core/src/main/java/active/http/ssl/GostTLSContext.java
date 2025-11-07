package active.http.ssl;

import active.http.ssl.store.CacertsStore;
import active.http.ssl.store.JcpKeyStore;
import active.http.ssl.store.PfxKeyStore;

import javax.net.ssl.*;
import java.lang.reflect.Constructor;
import java.security.*;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509CertSelector;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Реализация GOST TLS контекста на основе CryptoPro JCSP.
 *
 * <p>Эта реализация следует официальному шаблону CryptoPro для создания
 * SSL/TLS контекстов с поддержкой криптографии ГОСТ. Использует:
 * <ul>
 *   <li>JCP KeyStore для доверенных сертификатов</li>
 *   <li>PFX KeyStore для клиентских сертификатов</li>
 *   <li>JavaTLSCertPathManagerParameters для валидации путей</li>
 *   <li>PKIXBuilderParameters для построения цепочки сертификатов</li>
 * </ul>
 *
 * <p><b>Пример использования:</b>
 * <pre>
 * GostTLSContext context = GostTLSContext.builder()
 *     .pfxCertificate("certs/cert.pfx", "password")
 *     .build();
 *
 * SSLSocketFactory factory = context.getSocketFactory();
 * </pre>
 *
 * @see <a href="https://habr.com/ru/companies/alfastrah/articles/823974/">Руководство по конфигурации GOST TLS</a>
 */
public final class GostTLSContext {
    private static final Logger logger = Logger.getLogger(GostTLSContext.class.getName());

    private static final String GOST_PROTOCOL = "GostTLSv1.3";
    private static final String GOST_CERTIFICATE_ALGORITHM = "GostX509";
    private static final String COLLECTION_TYPE = "Collection";
    private static final String JAVA_TLS_CERT_PATH_MANAGER_PARAMS_CLASS =
        "ru.CryptoPro.ssl.JavaTLSCertPathManagerParameters";

    private final SSLContext sslContext;
    private final PfxKeyStore pfxKeyStore;

    /**
     * Внутренний конструктор. Используйте {@link #builder()} для создания экземпляров.
     */
    GostTLSContext(
        PfxKeyStore pfxKeyStore,
        boolean disableVerification,
        boolean enableRevocationCheck
    ) {
        this.pfxKeyStore = pfxKeyStore;

        try {
            this.sslContext = createSSLContext(pfxKeyStore, disableVerification, enableRevocationCheck);
            logger.info("GostTLSContext initialized successfully with protocol: " + GOST_PROTOCOL);
        } catch (Exception e) {
            throw new RuntimeException(
                "Failed to create GOST SSL context. " +
                "Ensure CryptoPro JCSP is properly installed and licensed.",
                e
            );
        }
    }

    /**
     * Создать новый построитель для конфигурации GostTLSContext.
     *
     * @return новый экземпляр построителя
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Получить настроенный SSL контекст.
     *
     * @return SSL контекст
     */
    public SSLContext getSslContext() {
        return sslContext;
    }

    /**
     * Получить SSL socket factory из этого контекста.
     *
     * @return SSL socket factory
     */
    public SSLSocketFactory getSocketFactory() {
        return sslContext.getSocketFactory();
    }

    /**
     * Создать и настроить GOST SSL контекст.
     */
    private SSLContext createSSLContext(
        PfxKeyStore pfxKeyStore,
        boolean disableVerification,
        boolean enableRevocationCheck
    ) throws Exception {

        logger.fine("Creating GOST SSL context with protocol: " + GOST_PROTOCOL);

        // Initialize CryptoPro providers
        CryptoProProvider.initialize();

        // Create stores
        CacertsStore cacertsStore = new CacertsStore();
        JcpKeyStore jcpKeyStore = new JcpKeyStore(cacertsStore);

        // Prepare KeyManagers
        KeyManager[] keyManagers = null;
        if (pfxKeyStore != null) {
            keyManagers = createGostKeyManagers(pfxKeyStore, jcpKeyStore, cacertsStore, enableRevocationCheck);
        }

        // Prepare TrustManagers
        TrustManager[] trustManagers = createGostTrustManagers(jcpKeyStore);

        // Create SSL context
        SSLContext context = SSLContext.getInstance(GOST_PROTOCOL);
        context.init(keyManagers, trustManagers, new SecureRandom());

        return context;
    }

    /**
     * Создать GOST Key Managers для аутентификации клиентского сертификата.
     *
     * <p>Этот метод следует официальному шаблону CryptoPro:
     * <ol>
     *   <li>Создать KeyManagerFactory с алгоритмом GostX509</li>
     *   <li>Построить PKIXBuilderParameters с JCP KeyStore</li>
     *   <li>Включить/отключить проверку отзыва на основе конфигурации</li>
     *   <li>Добавить сертификаты cacerts в CertStore</li>
     *   <li>Инициализировать JavaTLSCertPathManagerParameters с PFX хранилищем</li>
     *   <li>Установить PKIX параметры и инициализировать фабрику</li>
     * </ol>
     *
     * @param enableRevocationCheck если true, включает проверку отзыва сертификатов через CDP.
     *                              Требует сетевого доступа к cdp.cryptopro.ru и vpnca.cryptopro.ru
     */
    private KeyManager[] createGostKeyManagers(
        PfxKeyStore pfxKeyStore,
        JcpKeyStore jcpKeyStore,
        CacertsStore cacertsStore,
        boolean enableRevocationCheck
    ) throws Exception {

        try {
            // Step 1: Create KeyManagerFactory with GOST algorithm
            KeyManagerFactory factory = KeyManagerFactory.getInstance(GOST_CERTIFICATE_ALGORITHM);
            logger.fine("Created KeyManagerFactory with algorithm: " + GOST_CERTIFICATE_ALGORITHM);

            // Step 2: Build PKIX parameters with JCP KeyStore
            KeyStore jcpStore = jcpKeyStore.prepareKeyStoreWithJcpCertificates();
            PKIXBuilderParameters pkixParameters = new PKIXBuilderParameters(
                jcpStore,
                new X509CertSelector()
            );

            // Step 3: Enable/disable revocation checking
            pkixParameters.setRevocationEnabled(enableRevocationCheck);
            if (enableRevocationCheck) {
                logger.info("Certificate revocation checking ENABLED (requires CDP access: cdp.cryptopro.ru, vpnca.cryptopro.ru)");
            } else {
                logger.warning("Certificate revocation checking DISABLED (not recommended for production)");
            }

            // Step 4: Add cacerts certificates to CertStore for revocation checking
            java.security.cert.CertStore certStore = java.security.cert.CertStore.getInstance(
                COLLECTION_TYPE,
                new CollectionCertStoreParameters(cacertsStore.getCertificatesFromCacerts())
            );
            pkixParameters.setCertStores(Collections.singletonList(certStore));
            logger.fine("Added cacerts certificates to PKIXBuilderParameters");

            // Step 5: Initialize JavaTLSCertPathManagerParameters with PFX KeyStore
            KeyStore pfxStore = pfxKeyStore.getKeyStore();
            Object managerParameters = createJavaTLSCertPathManagerParameters(pfxStore);

            // Step 6: Set PKIX parameters and initialize factory
            setParameters(managerParameters, pkixParameters);
            factory.init((ManagerFactoryParameters) managerParameters);

            logger.info("GOST KeyManagers created successfully");
            return factory.getKeyManagers();

        } catch (Exception e) {
            logger.log(Level.WARNING, "Failed to create GOST KeyManagers", e);
            throw new KeyManagementException("Failed to initialize GOST key managers", e);
        }
    }

    /**
     * Создать GOST Trust Managers для проверки серверных сертификатов.
     *
     * <p>Использует JCP KeyStore с сертификатами из cacerts для валидации доверия.
     */
    private TrustManager[] createGostTrustManagers(JcpKeyStore jcpKeyStore) throws Exception {
        try {
            KeyStore keyStore = jcpKeyStore.prepareKeyStoreWithJcpCertificates();

            TrustManagerFactory factory = TrustManagerFactory.getInstance(GOST_CERTIFICATE_ALGORITHM);
            factory.init(keyStore);

            logger.info("GOST TrustManagers created successfully");
            return factory.getTrustManagers();

        } catch (Exception e) {
            logger.log(Level.WARNING, "Failed to create GOST TrustManagers", e);
            throw new KeyManagementException("Failed to initialize GOST trust managers", e);
        }
    }

    /**
     * Очистить ресурсы.
     */
    public void close() {
        if (pfxKeyStore != null) {
            pfxKeyStore.clearPassword();
        }
    }

    /**
     * Создать экземпляр JavaTLSCertPathManagerParameters используя рефлексию.
     *
     * @param keyStore KeyStore для использования
     * @return экземпляр JavaTLSCertPathManagerParameters
     * @throws RuntimeException если класс не может быть создан
     */
    private Object createJavaTLSCertPathManagerParameters(KeyStore keyStore) {
        try {
            Class<?> paramsClass = Class.forName(JAVA_TLS_CERT_PATH_MANAGER_PARAMS_CLASS);
            Constructor<?> constructor = paramsClass.getConstructor(KeyStore.class, char[].class);
            return constructor.newInstance(keyStore, new char[0]);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(
                "CryptoPro SSL library not found. " +
                "Class " + JAVA_TLS_CERT_PATH_MANAGER_PARAMS_CLASS + " is not available. " +
                "Please install CryptoPro CPSSL libraries to use GOST TLS.",
                e
            );
        } catch (Exception e) {
            throw new RuntimeException(
                "Failed to create JavaTLSCertPathManagerParameters instance",
                e
            );
        }
    }

    /**
     * Установить PKIX параметры используя рефлексию.
     *
     * @param managerParameters объект параметров менеджера
     * @param pkixParameters PKIX параметры для установки
     * @throws RuntimeException если метод не может быть вызван
     */
    private void setParameters(Object managerParameters, PKIXBuilderParameters pkixParameters) {
        try {
            managerParameters.getClass()
                .getMethod("setParameters", PKIXBuilderParameters.class)
                .invoke(managerParameters, pkixParameters);
        } catch (Exception e) {
            throw new RuntimeException(
                "Failed to set PKIX parameters on JavaTLSCertPathManagerParameters",
                e
            );
        }
    }

    /**
     * Построитель для GostTLSContext.
     */
    public static class Builder {
        private PfxKeyStore pfxKeyStore;
        private boolean disableVerification = false;
        private boolean enableRevocationCheck = true; // Enabled by default for security

        /**
         * Установить путь к PFX сертификату и пароль.
         *
         * @param pfxPath путь к PFX файлу
         * @param password пароль PFX
         * @return этот построитель
         */
        public Builder pfxCertificate(String pfxPath, String password) {
            this.pfxKeyStore = new PfxKeyStore(pfxPath, password, false);
            return this;
        }

        /**
         * Установить PFX сертификат из ресурса classpath.
         *
         * @param resourcePath путь к PFX ресурсу (например, "certs/cert.pfx")
         * @param password пароль PFX
         * @return этот построитель
         */
        public Builder pfxResource(String resourcePath, String password) {
            this.pfxKeyStore = new PfxKeyStore(resourcePath, password, true);
            return this;
        }

        /**
         * Установить пользовательский PFX KeyStore.
         *
         * @param pfxKeyStore PFX KeyStore
         * @return этот построитель
         */
        public Builder pfxKeyStore(PfxKeyStore pfxKeyStore) {
            this.pfxKeyStore = pfxKeyStore;
            return this;
        }

        /**
         * Отключить проверку сертификатов (только для тестирования).
         *
         * @param disable true для отключения проверки
         * @return этот построитель
         */
        public Builder disableVerification(boolean disable) {
            this.disableVerification = disable;
            if (disable) {
                logger.warning(
                    "Certificate verification will be DISABLED. " +
                    "This should only be used for testing!"
                );
            }
            return this;
        }

        /**
         * Включить или отключить проверку отзыва сертификатов через CDP.
         *
         * <p><b>Важно:</b> Проверка отзыва ВКЛЮЧЕНА по умолчанию для безопасности.
         * Требует сетевого доступа к CDP серверам CryptoPro:
         * <ul>
         *   <li>http://cdp.cryptopro.ru/ra/cdp/*</li>
         *   <li>http://vpnca.cryptopro.ru/cdp/*</li>
         * </ul>
         *
         * <p>Отключайте проверку отзыва только в тестовых/разработочных окружениях,
         * где доступ к CDP недоступен. Это НЕ рекомендуется для production.
         *
         * @param enable true для включения проверки отзыва (по умолчанию), false для отключения
         * @return этот построитель
         */
        public Builder enableRevocationCheck(boolean enable) {
            this.enableRevocationCheck = enable;
            if (!enable) {
                logger.warning(
                    "Certificate revocation checking will be DISABLED. " +
                    "This is NOT recommended for production environments!"
                );
            }
            return this;
        }

        /**
         * Построить GostTLSContext.
         *
         * @return новый экземпляр GostTLSContext
         */
        public GostTLSContext build() {
            return new GostTLSContext(pfxKeyStore, disableVerification, enableRevocationCheck);
        }
    }
}
