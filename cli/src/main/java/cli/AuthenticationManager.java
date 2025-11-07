package cli;

import active.auth.AuthCredentials;
import active.auth.AuthenticationHelper;
import active.http.HttpClient;
import active.model.ApiEndpoint;
import active.scanner.ScanContext;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * Менеджер аутентификации, отвечающий за настройку аутентификации и создание тестовых пользователей.
 * Инкапсулирует логику автоматической аутентификации и управления учетными данными пользователей.
 *
 * @author API Security Analyzer Team
 * @since 1.0
 */
public final class AuthenticationManager {
    private static final Logger logger = Logger.getLogger(AuthenticationManager.class.getName());

    private final UnifiedAnalyzer.AnalyzerConfig config;

    /**
     * Создает новый менеджер аутентификации с указанной конфигурацией.
     *
     * @param config конфигурация анализатора
     */
    public AuthenticationManager(UnifiedAnalyzer.AnalyzerConfig config) {
        this.config = config;
    }

    /**
     * Настраивает аутентификацию для контекста сканирования.
     * Обрабатывает три сценария:
     * 1. Использование предоставленного заголовка аутентификации
     * 2. Автоматическая аутентификация (если включена)
     * 3. Обработка предоставленных тестовых пользователей
     *
     * @param contextBuilder билдер контекста сканирования
     * @param baseUrl базовый URL для аутентификации
     * @param endpoints список конечных точек API
     * @return количество настроенных тестовых пользователей (для логирования)
     */
    public int setupAuthentication(ScanContext.Builder contextBuilder,
                                   String baseUrl,
                                   List<ApiEndpoint> endpoints) {

        // Сценарий 1: Использование предоставленного заголовка аутентификации
        if (config.getAuthHeader() != null) {
            return handleProvidedAuthHeader(contextBuilder);
        }

        // Сценарий 2: Автоматическая аутентификация
        if (config.isAutoAuth()) {
            return handleAutoAuthentication(contextBuilder, baseUrl, endpoints);
        }

        // Сценарий 3: Только обработка тестовых пользователей (без автоматической аутентификации)
        if (config.getTestUsers() != null && !config.getTestUsers().isEmpty()) {
            return handleProvidedTestUsers(contextBuilder, baseUrl, endpoints);
        }

        return 0;
    }

    /**
     * Обрабатывает предоставленный заголовок аутентификации.
     */
    private int handleProvidedAuthHeader(ScanContext.Builder contextBuilder) {
        String[] parts = config.getAuthHeader().split(":", 2);
        if (parts.length == 2) {
            contextBuilder.addAuthHeader(parts[0].trim(), parts[1].trim());
            logger.info("Using provided authentication header");
            config.getProgressListener().onLog("INFO", "Using provided authentication header");
        }
        return 0;
    }

    /**
     * Выполняет автоматическую аутентификацию.
     */
    private int handleAutoAuthentication(ScanContext.Builder contextBuilder,
                                        String baseUrl,
                                        List<ApiEndpoint> endpoints) {
        logger.info("Attempting automatic authentication...");
        config.getProgressListener().onStepComplete(2, "Attempting automatic authentication...");

        // Создание HTTP клиента для аутентификации
        HttpClient authHttpClient = HttpClientHelper.createClient(config);
        AuthenticationHelper authHelper = new AuthenticationHelper(authHttpClient, baseUrl);

        // Попытка аутентификации
        Optional<AuthCredentials> primaryCreds = authHelper.attemptAutoAuth(endpoints);

        if (primaryCreds.isEmpty()) {
            logger.warning("⚠ Auto-authentication failed. Protected endpoints may not be testable.");
            logger.info("  Tip: Provide authentication via --auth-header or ensure API has registration endpoint");
            config.getProgressListener().onLog("WARNING", "Auto-authentication failed - protected endpoints may not be testable");
            return 0;
        }

        // Успешная аутентификация
        AuthCredentials creds = primaryCreds.get();
        String authHeader = creds.getAuthorizationHeader();
        if (authHeader != null) {
            contextBuilder.addAuthHeader("Authorization", authHeader);
            logger.info("✓ Auto-authentication successful for user: " + creds.getUsername());
            config.getProgressListener().onLog("INFO", "✓ Authentication successful" +
                (creds.getUsername() != null ? " for user: " + creds.getUsername() : ""));
        }

        // Сохранение основных учетных данных в общих данных
        Map<String, Object> sharedDataMap = new java.util.HashMap<>();
        sharedDataMap.put("primaryCredentials", creds);

        // Обработка тестовых пользователей
        int testUserCount = setupTestUsers(sharedDataMap, authHelper, endpoints);

        contextBuilder.sharedData(sharedDataMap);
        return testUserCount;
    }

    /**
     * Настраивает тестовых пользователей для BOLA тестирования.
     */
    private int setupTestUsers(Map<String, Object> sharedDataMap,
                              AuthenticationHelper authHelper,
                              List<ApiEndpoint> endpoints) {

        // Использование предоставленных тестовых пользователей
        if (config.getTestUsers() != null && !config.getTestUsers().isEmpty()) {
            logger.info("Processing " + config.getTestUsers().size() + " provided test user(s)...");
            config.getProgressListener().onStepComplete(3, "Authenticating " + config.getTestUsers().size() + " test user(s)...");

            List<AuthCredentials> authenticatedUsers = authenticateProvidedUsers(
                config.getTestUsers(), authHelper, endpoints);

            sharedDataMap.put("testUsers", authenticatedUsers);
            logger.info("✓ Processed " + authenticatedUsers.size() + " test user(s)");
            config.getProgressListener().onLog("INFO", "✓ Configured " + authenticatedUsers.size() + " test user(s) for BOLA testing");
            return authenticatedUsers.size();
        }

        // Создание новых тестовых пользователей
        if (config.isCreateTestUsers()) {
            logger.info("Creating additional test users for BOLA testing...");
            config.getProgressListener().onStepComplete(3, "Creating test users for BOLA testing...");
            List<AuthCredentials> testUsers = authHelper.createTestUsers(endpoints, 2);
            if (!testUsers.isEmpty()) {
                sharedDataMap.put("testUsers", testUsers);
                logger.info("✓ Created " + testUsers.size() + " additional test users");
                config.getProgressListener().onLog("INFO", "✓ Created " + testUsers.size() + " test user(s)");
                return testUsers.size();
            }
        }

        return 0;
    }

    /**
     * Обрабатывает предоставленных тестовых пользователей без автоматической аутентификации.
     */
    private int handleProvidedTestUsers(ScanContext.Builder contextBuilder,
                                       String baseUrl,
                                       List<ApiEndpoint> endpoints) {
        logger.info("Processing " + config.getTestUsers().size() + " provided test user(s) (auto-auth disabled)");

        // Создание HTTP клиента для аутентификации
        HttpClient authHttpClient = HttpClientHelper.createBasicClient(config.isVerifySsl());
        AuthenticationHelper authHelper = new AuthenticationHelper(authHttpClient, baseUrl);

        List<AuthCredentials> authenticatedUsers = authenticateProvidedUsers(
            config.getTestUsers(), authHelper, endpoints);

        contextBuilder.sharedData(Map.of("testUsers", authenticatedUsers));
        logger.info("✓ Processed " + authenticatedUsers.size() + " test user(s)");

        return authenticatedUsers.size();
    }

    /**
     * Аутентифицирует предоставленных тестовых пользователей, у которых есть clientId/clientSecret.
     * Пользователи, у которых уже есть токены или username/password, передаются без изменений.
     *
     * @param providedUsers предоставленные пользователи
     * @param authHelper помощник для аутентификации
     * @param endpoints список конечных точек API
     * @return список аутентифицированных пользователей
     */
    private List<AuthCredentials> authenticateProvidedUsers(
            List<AuthCredentials> providedUsers,
            AuthenticationHelper authHelper,
            List<ApiEndpoint> endpoints) {

        List<AuthCredentials> result = new ArrayList<>();

        // Поиск конечной точки токена для потока учетных данных клиента
        ApiEndpoint tokenEndpoint = endpoints.stream()
            .filter(ep -> ep.getPath().contains("token") && ep.getMethod().equals("POST"))
            .findFirst()
            .orElse(null);

        for (AuthCredentials user : providedUsers) {
            // Проверка наличия clientId/clientSecret без токена
            boolean hasClientCreds = user.getAdditionalHeaders().containsKey("X-Client-Id") &&
                                    user.getAdditionalHeaders().containsKey("X-Client-Secret");

            if (hasClientCreds && !user.hasToken() && tokenEndpoint != null) {
                String clientId = user.getAdditionalHeaders().get("X-Client-Id");
                String clientSecret = user.getAdditionalHeaders().get("X-Client-Secret");

                logger.info("Authenticating test user with client credentials: " + clientId);

                Optional<AuthCredentials> authenticated = authHelper.authenticateWithClientCredentials(
                    tokenEndpoint, clientId, clientSecret);

                if (authenticated.isPresent()) {
                    logger.info("✓ Successfully authenticated client: " + clientId);
                    result.add(authenticated.get());
                } else {
                    logger.warning("⚠ Failed to authenticate client: " + clientId + " - using without token");
                    result.add(user);
                }
            } else {
                // Пользователь уже имеет токен, или использует username/password, или конечная точка токена не найдена
                result.add(user);
            }
        }

        return result;
    }
}
