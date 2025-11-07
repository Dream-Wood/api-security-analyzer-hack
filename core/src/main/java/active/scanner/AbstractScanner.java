package active.scanner;

import active.http.HttpClient;
import active.model.ApiEndpoint;
import active.model.TestRequest;
import active.model.TestResponse;
import active.model.VulnerabilityReport;

import java.time.Instant;
import java.util.*;
import java.util.logging.Logger;

/**
 * Абстрактный базовый класс для сканеров уязвимостей.
 * Предоставляет общую функциональность и уменьшает шаблонный код для реализаций сканеров.
 *
 * <p>Подклассы должны:
 * <ul>
 *   <li>Определить метаданные сканера (ID, имя, описание)</li>
 *   <li>Реализовать {@link #isApplicable(ApiEndpoint)} для фильтрации эндпоинтов</li>
 *   <li>Реализовать {@link #performScan(ApiEndpoint, HttpClient, ScanContext)} с логикой тестирования</li>
 * </ul>
 */
public abstract class AbstractScanner implements VulnerabilityScanner {
    protected final Logger logger = Logger.getLogger(getClass().getName());
    protected ScannerConfig config;

    protected AbstractScanner() {
        this.config = ScannerConfig.defaultConfig();
    }

    protected AbstractScanner(ScannerConfig config) {
        this.config = config != null ? config : ScannerConfig.defaultConfig();
    }

    @Override
    public final ScanResult scan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();

        try {
            logger.info("Starting " + getName() + " scan on: " + endpoint);

            // Delegate to subclass implementation
            return performScan(endpoint, httpClient, context);

        } catch (Exception e) {
            logger.warning(getName() + " scan failed for " + endpoint + ": " + e.getMessage());

            return ScanResult.builder()
                .scannerId(getId())
                .endpoint(endpoint)
                .status(ScanResult.ScanStatus.FAILED)
                .startTime(startTime)
                .endTime(Instant.now())
                .errorMessage("Scan failed: " + e.getMessage())
                .build();
        }
    }

    /**
     * Выполнить фактическое сканирование на уязвимости.
     * Подклассы реализуют этот метод со своей специфической логикой тестирования.
     *
     * @param endpoint эндпоинт для сканирования
     * @param httpClient HTTP клиент для использования при тестировании
     * @param context контекст сканирования с конфигурацией и состоянием
     * @return результат сканирования с обнаруженными уязвимостями
     */
    protected abstract ScanResult performScan(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    );

    @Override
    public ScannerConfig getConfig() {
        return config;
    }

    @Override
    public void setConfig(ScannerConfig config) {
        this.config = config != null ? config : ScannerConfig.defaultConfig();
    }

    /**
     * Вспомогательный метод для создания успешного результата сканирования.
     *
     * @param endpoint отсканированный эндпоинт
     * @param vulnerabilities список обнаруженных уязвимостей
     * @param totalTests общее количество выполненных тестов
     * @param startTime время начала сканирования
     * @return результат сканирования
     */
    protected ScanResult createSuccessResult(
        ApiEndpoint endpoint,
        List<VulnerabilityReport> vulnerabilities,
        int totalTests,
        Instant startTime
    ) {
        return ScanResult.builder()
            .scannerId(getId())
            .endpoint(endpoint)
            .status(ScanResult.ScanStatus.SUCCESS)
            .vulnerabilities(vulnerabilities)
            .totalTests(totalTests)
            .failedTests(0)
            .startTime(startTime)
            .endTime(Instant.now())
            .build();
    }

    /**
     * Вспомогательный метод для проверки, указывает ли ответ на успешный обход аутентификации.
     *
     * @param response HTTP ответ
     * @return true если ответ предполагает успешный несанкционированный доступ
     */
    protected boolean isSuccessfulUnauthorizedAccess(TestResponse response) {
        int status = response.getStatusCode();
        // 200 OK, 201 Created, or any 2xx status (except 204 No Content which might be normal)
        return status >= 200 && status < 300 && status != 204;
    }

    /**
     * Вспомогательный метод для проверки, требует ли ответ аутентификацию.
     *
     * @param response HTTP ответ
     * @return true если ответ указывает на отсутствующую/недействительную аутентификацию
     */
    protected boolean isAuthenticationRequired(TestResponse response) {
        int status = response.getStatusCode();
        // 401 Unauthorized or 403 Forbidden
        return status == 401 || status == 403;
    }

    /**
     * Вспомогательный метод для выполнения тестового запроса и логирования результата.
     * Реализует троттлинг на основе конфигурации сканера, чтобы избежать перегрузки production систем.
     *
     * @param httpClient HTTP клиент
     * @param request тестовый запрос
     * @param testName имя теста для логирования
     * @return ответ
     */
    protected TestResponse executeTest(HttpClient httpClient, TestRequest request, String testName) {
        logger.fine("Executing test: " + testName);

        // Apply throttling delay if configured (to avoid DoS on production)
        int delayMs = config.getRequestDelayMs();
        if (delayMs > 0) {
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.warning("Throttling delay interrupted: " + e.getMessage());
            }
        }

        return httpClient.execute(request);
    }
}
