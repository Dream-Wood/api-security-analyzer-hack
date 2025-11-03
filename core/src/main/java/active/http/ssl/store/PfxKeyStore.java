package active.http.ssl.store;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.logging.Logger;

/**
 * PFX KeyStore implementation for loading client certificates.
 *
 * <p>This class loads PFX (PKCS#12) certificates that contain private keys
 * for client authentication in GOST TLS connections.
 */
public final class PfxKeyStore {
    private static final Logger logger = Logger.getLogger(PfxKeyStore.class.getName());
    private static final String PFX_STORE_TYPE = "PFXSTORE";

    private KeyStore keyStore;
    private final String pfxPath;
    private final char[] password;
    private final boolean isResource;

    /**
     * Create PFX store from file path.
     *
     * @param pfxPath path to PFX file
     * @param password PFX password
     */
    public PfxKeyStore(String pfxPath, String password) {
        this(pfxPath, password, false);
    }

    /**
     * Create PFX store from resource or file path.
     *
     * @param pfxPath path to PFX file or resource
     * @param password PFX password
     * @param isResource true if path is a resource, false if file path
     */
    public PfxKeyStore(String pfxPath, String password, boolean isResource) {
        this.pfxPath = pfxPath;
        this.password = password != null ? password.toCharArray() : new char[0];
        this.isResource = isResource;
    }

    /**
     * Get the loaded KeyStore instance.
     * Loads the PFX certificate on first access and caches it.
     *
     * @return KeyStore instance containing the PFX certificate
     * @throws RuntimeException if PFX cannot be loaded
     */
    public KeyStore getKeyStore() {
        if (keyStore != null) {
            return keyStore;
        }

        try {
            byte[] certBytes;
            if (isResource) {
                certBytes = loadFromResource(pfxPath);
            } else {
                certBytes = loadFromFile(pfxPath);
            }

            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(certBytes);
            keyStore = KeyStore.getInstance(PFX_STORE_TYPE);
            keyStore.load(byteArrayInputStream, password);

            logger.info("Loaded PFX certificate from: " + pfxPath);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException exception) {
            logger.severe("Failed to load PFX keystore: " + exception.getMessage());
            throw new RuntimeException(
                "Failed to load PFX certificate from: " + pfxPath,
                exception
            );
        }

        return keyStore;
    }

    /**
     * Load PFX from classpath resource.
     */
    private byte[] loadFromResource(String resourcePath) throws IOException {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IOException("Resource not found: " + resourcePath);
            }
            return is.readAllBytes();
        }
    }

    /**
     * Load PFX from file system.
     */
    private byte[] loadFromFile(String filePath) throws IOException {
        try (InputStream is = new FileInputStream(filePath)) {
            return is.readAllBytes();
        }
    }

    /**
     * Clear the password from memory.
     */
    public void clearPassword() {
        if (password != null) {
            java.util.Arrays.fill(password, '\0');
        }
    }
}
