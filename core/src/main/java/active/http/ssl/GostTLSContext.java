package active.http.ssl;

import active.http.ssl.store.CacertsStore;
import active.http.ssl.store.JcpKeyStore;
import active.http.ssl.store.PfxKeyStore;
import ru.CryptoPro.ssl.JavaTLSCertPathManagerParameters;

import javax.net.ssl.*;
import java.security.*;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509CertSelector;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * GOST TLS Context implementation based on CryptoPro JCSP.
 *
 * <p>This implementation follows the official CryptoPro pattern for creating
 * SSL/TLS contexts with GOST cryptography support. It uses:
 * <ul>
 *   <li>JCP KeyStore for trusted certificates</li>
 *   <li>PFX KeyStore for client certificates</li>
 *   <li>JavaTLSCertPathManagerParameters for path validation</li>
 *   <li>PKIXBuilderParameters for certificate chain building</li>
 * </ul>
 *
 * <p><b>Usage example:</b>
 * <pre>
 * GostTLSContext context = GostTLSContext.builder()
 *     .pfxCertificate("certs/cert.pfx", "password")
 *     .build();
 *
 * SSLSocketFactory factory = context.getSocketFactory();
 * </pre>
 *
 * @see <a href="https://habr.com/ru/companies/alfastrah/articles/823974/">GOST TLS Configuration Guide</a>
 */
public final class GostTLSContext {
    private static final Logger logger = Logger.getLogger(GostTLSContext.class.getName());

    private static final String GOST_PROTOCOL = "GostTLSv1.3";
    private static final String GOST_CERTIFICATE_ALGORITHM = "GostX509";
    private static final String COLLECTION_TYPE = "Collection";

    private final SSLContext sslContext;
    private final PfxKeyStore pfxKeyStore;

    /**
     * Internal constructor. Use {@link #builder()} to create instances.
     */
    GostTLSContext(
        PfxKeyStore pfxKeyStore,
        boolean disableVerification
    ) {
        this.pfxKeyStore = pfxKeyStore;

        try {
            this.sslContext = createSSLContext(pfxKeyStore, disableVerification);
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
     * Create a new builder for configuring GostTLSContext.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Get the configured SSL context.
     *
     * @return the SSL context
     */
    public SSLContext getSslContext() {
        return sslContext;
    }

    /**
     * Get the SSL socket factory from this context.
     *
     * @return the SSL socket factory
     */
    public SSLSocketFactory getSocketFactory() {
        return sslContext.getSocketFactory();
    }

    /**
     * Create and configure the GOST SSL context.
     */
    private SSLContext createSSLContext(
        PfxKeyStore pfxKeyStore,
        boolean disableVerification
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
            keyManagers = createGostKeyManagers(pfxKeyStore, jcpKeyStore, cacertsStore);
        }

        // Prepare TrustManagers
        TrustManager[] trustManagers = createGostTrustManagers(jcpKeyStore);

        // Create SSL context
        SSLContext context = SSLContext.getInstance(GOST_PROTOCOL);
        context.init(keyManagers, trustManagers, new SecureRandom());

        return context;
    }

    /**
     * Create GOST Key Managers for client certificate authentication.
     *
     * <p>This method follows the official CryptoPro pattern:
     * <ol>
     *   <li>Create KeyManagerFactory with GostX509 algorithm</li>
     *   <li>Build PKIXBuilderParameters with JCP KeyStore</li>
     *   <li>Enable revocation checking</li>
     *   <li>Add cacerts certificates to CertStore</li>
     *   <li>Initialize JavaTLSCertPathManagerParameters with PFX store</li>
     *   <li>Set PKIX parameters and initialize factory</li>
     * </ol>
     */
    private KeyManager[] createGostKeyManagers(
        PfxKeyStore pfxKeyStore,
        JcpKeyStore jcpKeyStore,
        CacertsStore cacertsStore
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

            // Step 3: Enable revocation checking
            pkixParameters.setRevocationEnabled(true);
            logger.fine("Revocation checking enabled");

            // Step 4: Add cacerts certificates to CertStore for revocation checking
            java.security.cert.CertStore certStore = java.security.cert.CertStore.getInstance(
                COLLECTION_TYPE,
                new CollectionCertStoreParameters(cacertsStore.getCertificatesFromCacerts())
            );
            pkixParameters.setCertStores(Collections.singletonList(certStore));
            logger.fine("Added cacerts certificates to PKIXBuilderParameters");

            // Step 5: Initialize JavaTLSCertPathManagerParameters with PFX KeyStore
            KeyStore pfxStore = pfxKeyStore.getKeyStore();
            JavaTLSCertPathManagerParameters managerParameters =
                new JavaTLSCertPathManagerParameters(pfxStore, new char[0]);

            // Step 6: Set PKIX parameters and initialize factory
            managerParameters.setParameters(pkixParameters);
            factory.init(managerParameters);

            logger.info("GOST KeyManagers created successfully");
            return factory.getKeyManagers();

        } catch (Exception e) {
            logger.log(Level.WARNING, "Failed to create GOST KeyManagers", e);
            throw new KeyManagementException("Failed to initialize GOST key managers", e);
        }
    }

    /**
     * Create GOST Trust Managers for server certificate verification.
     *
     * <p>Uses JCP KeyStore with certificates from cacerts for trust validation.
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
     * Clean up resources.
     */
    public void close() {
        if (pfxKeyStore != null) {
            pfxKeyStore.clearPassword();
        }
    }

    /**
     * Builder for GostTLSContext.
     */
    public static class Builder {
        private PfxKeyStore pfxKeyStore;
        private boolean disableVerification = false;

        /**
         * Set PFX certificate path and password.
         *
         * @param pfxPath path to PFX file
         * @param password PFX password
         * @return this builder
         */
        public Builder pfxCertificate(String pfxPath, String password) {
            this.pfxKeyStore = new PfxKeyStore(pfxPath, password, false);
            return this;
        }

        /**
         * Set PFX certificate from classpath resource.
         *
         * @param resourcePath path to PFX resource (e.g., "certs/cert.pfx")
         * @param password PFX password
         * @return this builder
         */
        public Builder pfxResource(String resourcePath, String password) {
            this.pfxKeyStore = new PfxKeyStore(resourcePath, password, true);
            return this;
        }

        /**
         * Set custom PFX KeyStore.
         *
         * @param pfxKeyStore the PFX KeyStore
         * @return this builder
         */
        public Builder pfxKeyStore(PfxKeyStore pfxKeyStore) {
            this.pfxKeyStore = pfxKeyStore;
            return this;
        }

        /**
         * Disable certificate verification (for testing only).
         *
         * @param disable true to disable verification
         * @return this builder
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
         * Build the GostTLSContext.
         *
         * @return a new GostTLSContext instance
         */
        public GostTLSContext build() {
            return new GostTLSContext(pfxKeyStore, disableVerification);
        }
    }
}
