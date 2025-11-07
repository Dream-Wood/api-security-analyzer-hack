package cli;

import active.http.HttpClient;
import active.http.HttpClientConfig;
import active.http.HttpClientFactory;

/**
 * Вспомогательный класс для создания HTTP клиентов с единообразной конфигурацией.
 * Устраняет дублирование кода при создании клиентов в различных частях приложения.
 *
 * @author API Security Analyzer Team
 * @since 1.0
 */
public final class HttpClientHelper {

    private HttpClientHelper() {
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Создает HTTP клиент на основе конфигурации анализатора.
     *
     * @param config конфигурация анализатора
     * @return настроенный HTTP клиент
     */
    public static HttpClient createClient(UnifiedAnalyzer.AnalyzerConfig config) {
        HttpClientConfig.Builder builder = HttpClientConfig.builder()
            .cryptoProtocol(config.getCryptoProtocol())
            .verifySsl(config.isVerifySsl());

        // Добавление конфигурации для GOST/CryptoPro
        if (config.getGostPfxPath() != null) {
            builder.addCustomSetting("pfxPath", config.getGostPfxPath());
        }
        if (config.getGostPfxPassword() != null) {
            builder.addCustomSetting("pfxPassword", config.getGostPfxPassword());
        }
        if (config.isGostPfxResource()) {
            builder.addCustomSetting("pfxResource", "true");
        }

        return HttpClientFactory.createClient(builder.build());
    }

    /**
     * Создает HTTP клиент с базовыми настройками (без GOST конфигурации).
     * Используется для простых случаев, когда криптография не требуется.
     *
     * @param verifySsl проверять ли SSL сертификаты
     * @return настроенный HTTP клиент
     */
    public static HttpClient createBasicClient(boolean verifySsl) {
        HttpClientConfig config = HttpClientConfig.builder()
            .verifySsl(verifySsl)
            .build();
        return HttpClientFactory.createClient(config);
    }
}
