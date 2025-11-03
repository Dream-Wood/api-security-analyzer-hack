package active.http.ssl.store;

import ru.CryptoPro.JCP.JCP;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;

/**
 * JCP KeyStore implementation for storing GOST certificates.
 *
 * <p>This class creates a JCP-based keystore and populates it with trusted
 * certificates from the system's cacerts store. The JCP keystore is used
 * for GOST TLS operations.
 */
public final class JcpKeyStore {
    private static final Logger logger = Logger.getLogger(JcpKeyStore.class.getName());

    private final CacertsStore cacertsStore;

    public JcpKeyStore(CacertsStore cacertsStore) {
        this.cacertsStore = cacertsStore;
    }

    /**
     * Prepare JCP KeyStore with GOST certificates from cacerts.
     *
     * <p>Creates a new JCP KeyStore instance, loads it, and populates it
     * with all trusted certificates from the system's cacerts store.
     *
     * @return KeyStore instance with JCP type containing trusted certificates
     * @throws RuntimeException if keystore cannot be created or loaded
     */
    public KeyStore prepareKeyStoreWithJcpCertificates() {
        KeyStore keyStore;

        try {
            keyStore = KeyStore.getInstance(JCP.CERT_STORE_NAME);
            logger.info("Created JCP KeyStore with type: " + JCP.CERT_STORE_NAME);
        } catch (KeyStoreException exception) {
            logger.severe("Failed to create JCP KeyStore: " + exception.getMessage());
            throw new RuntimeException(
                "Failed to prepare JCP certificate store. " +
                "Ensure CryptoPro JCP libraries are properly installed.",
                exception
            );
        }

        try {
            keyStore.load(null, null);
            logger.fine("JCP KeyStore initialized");
        } catch (IOException | NoSuchAlgorithmException | CertificateException exception) {
            logger.severe("Failed to initialize JCP KeyStore: " + exception.getMessage());
            throw new RuntimeException(
                "Failed to initialize JCP certificate store",
                exception
            );
        }

        // Load trusted certificates from cacerts
        List<X509Certificate> certificates = cacertsStore.getCertificatesFromCacerts();

        try {
            for (X509Certificate cert : certificates) {
                String alias = UUID.randomUUID().toString();
                keyStore.setCertificateEntry(alias, cert);
            }
            logger.info("Added " + certificates.size() + " certificates to JCP KeyStore");
        } catch (KeyStoreException exception) {
            logger.severe("Failed to add certificates to JCP KeyStore: " + exception.getMessage());
            throw new RuntimeException(
                "Failed to add GOST certificates to JCP store",
                exception
            );
        }

        return keyStore;
    }
}
