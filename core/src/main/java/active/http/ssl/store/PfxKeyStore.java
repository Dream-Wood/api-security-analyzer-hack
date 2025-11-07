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
 * Реализация PFX KeyStore для загрузки клиентских сертификатов.
 *
 * <p>Этот класс загружает PFX (PKCS#12) сертификаты, которые содержат приватные ключи
 * для клиентской аутентификации в GOST TLS соединениях.
 */
public final class PfxKeyStore {
    private static final Logger logger = Logger.getLogger(PfxKeyStore.class.getName());
    private static final String PFX_STORE_TYPE = "PFXSTORE";

    private KeyStore keyStore;
    private final String pfxPath;
    private final char[] password;
    private final boolean isResource;

    /**
     * Создать PFX хранилище из пути к файлу.
     *
     * @param pfxPath путь к PFX файлу
     * @param password пароль PFX
     */
    public PfxKeyStore(String pfxPath, String password) {
        this(pfxPath, password, false);
    }

    /**
     * Создать PFX хранилище из ресурса или пути к файлу.
     *
     * @param pfxPath путь к PFX файлу или ресурсу
     * @param password пароль PFX
     * @param isResource true если путь к ресурсу, false если путь к файлу
     */
    public PfxKeyStore(String pfxPath, String password, boolean isResource) {
        this.pfxPath = pfxPath;
        this.password = password != null ? password.toCharArray() : new char[0];
        this.isResource = isResource;
    }

    /**
     * Получить загруженный экземпляр KeyStore.
     * Загружает PFX сертификат при первом обращении и кэширует его.
     *
     * @return экземпляр KeyStore, содержащий PFX сертификат
     * @throws RuntimeException если PFX не может быть загружен
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
     * Загрузить PFX из ресурса classpath.
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
     * Загрузить PFX из файловой системы.
     */
    private byte[] loadFromFile(String filePath) throws IOException {
        try (InputStream is = new FileInputStream(filePath)) {
            return is.readAllBytes();
        }
    }

    /**
     * Очистить пароль из памяти.
     */
    public void clearPassword() {
        if (password != null) {
            java.util.Arrays.fill(password, '\0');
        }
    }
}
