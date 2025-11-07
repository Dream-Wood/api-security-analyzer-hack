package active.http.ssl.store;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

/**
 * Хранилище для получения доверенных сертификатов из cacerts Java.
 *
 * <p>Этот класс извлекает все доверенные сертификаты из системного хранилища
 * cacerts, которое используется для проверки серверных сертификатов при TLS соединениях.
 */
public final class CacertsStore {
    private static final Logger logger = Logger.getLogger(CacertsStore.class.getName());

    /**
     * Получить список доверенных сертификатов из хранилища cacerts Java.
     *
     * @return список X509 сертификатов из cacerts
     * @throws RuntimeException если сертификаты не могут быть загружены
     */
    public List<X509Certificate> getCertificatesFromCacerts() {
        TrustManagerFactory trustManagerFactory;
        try {
            trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
            );
            trustManagerFactory.init((KeyStore) null);
        } catch (NoSuchAlgorithmException | KeyStoreException exception) {
            logger.severe("Failed to initialize TrustManager for cacerts: " + exception.getMessage());
            throw new RuntimeException(
                "Failed to load certificates from cacerts keystore",
                exception
            );
        }

        List<TrustManager> trustManagers = Arrays.asList(trustManagerFactory.getTrustManagers());
        List<X509Certificate> certificates = trustManagers.stream()
            .filter(X509TrustManager.class::isInstance)
            .map(X509TrustManager.class::cast)
            .map(trustManager -> Arrays.asList(trustManager.getAcceptedIssuers()))
            .flatMap(Collection::stream)
            .toList();

        logger.info("Loaded " + certificates.size() + " certificates from cacerts");
        return certificates;
    }
}
