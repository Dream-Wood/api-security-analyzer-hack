package active.http.ssl.store;

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;

/**
 * Реализация JCP KeyStore для хранения ГОСТ сертификатов.
 *
 * <p>Этот класс создает хранилище ключей на основе JCP и заполняет его доверенными
 * сертификатами из системного хранилища cacerts. JCP хранилище используется
 * для операций GOST TLS.
 *
 * <p><b>Примечание:</b> Этот класс требует наличия библиотек CryptoPro JCP.
 * Если библиотеки не найдены, будет выброшено RuntimeException.
 */
public final class JcpKeyStore {
    private static final Logger logger = Logger.getLogger(JcpKeyStore.class.getName());
    private static final String JCP_CLASS_NAME = "ru.CryptoPro.JCP.JCP";
    private static final String CERT_STORE_NAME_FIELD = "CERT_STORE_NAME";

    private final CacertsStore cacertsStore;

    public JcpKeyStore(CacertsStore cacertsStore) {
        this.cacertsStore = cacertsStore;
    }

    /**
     * Подготовить JCP KeyStore с ГОСТ сертификатами из cacerts.
     *
     * <p>Создает новый экземпляр JCP KeyStore, загружает его и заполняет
     * всеми доверенными сертификатами из системного хранилища cacerts.
     *
     * @return экземпляр KeyStore с типом JCP, содержащий доверенные сертификаты
     * @throws RuntimeException если хранилище не может быть создано или загружено
     */
    public KeyStore prepareKeyStoreWithJcpCertificates() {
        KeyStore keyStore;

        try {
            String certStoreName = getCertStoreName();
            keyStore = KeyStore.getInstance(certStoreName);
            logger.info("Created JCP KeyStore with type: " + certStoreName);
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

    /**
     * Получить значение константы JCP CERT_STORE_NAME используя рефлексию.
     *
     * @return имя хранилища сертификатов
     * @throws RuntimeException если класс CryptoPro JCP недоступен
     */
    private String getCertStoreName() {
        try {
            Class<?> jcpClass = Class.forName(JCP_CLASS_NAME);
            Field field = jcpClass.getField(CERT_STORE_NAME_FIELD);
            return (String) field.get(null);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(
                "CryptoPro JCP library not found. " +
                "Class " + JCP_CLASS_NAME + " is not available in classpath. " +
                "Please install CryptoPro JCP libraries to use GOST cryptography.",
                e
            );
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(
                "Failed to access " + CERT_STORE_NAME_FIELD + " from " + JCP_CLASS_NAME,
                e
            );
        }
    }
}
