package active.http.ssl;

import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

/**
 * Permissive Trust Manager, который доверяет всем сертификатам.
 *
 * <p><b>ВНИМАНИЕ:</b> Этот класс отключает проверку сертификатов и должен использоваться
 * ТОЛЬКО в тестовых окружениях. НЕ используйте в production!
 *
 * <p>Используется для обхода проверки SSL сертификатов когда:
 * <ul>
 *   <li>Тестирование с самоподписанными сертификатами</li>
 *   <li>Разработка без доступа к валидным CA</li>
 *   <li>Отладка SSL проблем</li>
 * </ul>
 *
 * <p><b>Пример использования:</b>
 * <pre>
 * TrustManager[] trustManagers = new TrustManager[]{new PermissiveTrustManager()};
 * SSLContext context = SSLContext.getInstance("GostTLSv1.3");
 * context.init(keyManagers, trustManagers, null);
 * </pre>
 */
public final class PermissiveTrustManager implements X509TrustManager {
    private static final Logger logger = Logger.getLogger(PermissiveTrustManager.class.getName());

    public PermissiveTrustManager() {
        logger.warning(
            "PermissiveTrustManager initialized - ALL certificates will be trusted! " +
            "This should ONLY be used in testing environments."
        );
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
        // Доверять всем клиентским сертификатам (не проверять)
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        // Доверять всем серверным сертификатам (не проверять)
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        // Принимать любых издателей
        return new X509Certificate[0];
    }
}
