package active.auth;

import active.http.HttpClient;
import active.model.ApiEndpoint;
import active.model.TestRequest;
import active.model.TestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Помощник для автоматической аутентификации во время тестирования безопасности API.
 * Обнаруживает эндпоинты регистрации и входа, создает тестовых пользователей.
 *
 * <p>Основные возможности:
 * <ul>
 *   <li>Автоматическое обнаружение эндпоинтов аутентификации</li>
 *   <li>Регистрация и вход тестовых пользователей</li>
 *   <li>Поддержка OAuth2 Client Credentials Flow</li>
 *   <li>Создание нескольких тестовых пользователей для BOLA тестов</li>
 *   <li>Извлечение токенов из JSON ответов</li>
 * </ul>
 */
public final class AuthenticationHelper {
    private static final Logger logger = Logger.getLogger(AuthenticationHelper.class.getName());

    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient httpClient;
    private final String baseUrl;

    // Patterns for finding authentication endpoints
    private static final List<Pattern> REGISTER_PATTERNS = List.of(
        Pattern.compile(".*/register.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/signup.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/sign-up.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/create-account.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/users/create.*", Pattern.CASE_INSENSITIVE)
    );

    private static final List<Pattern> LOGIN_PATTERNS = List.of(
        Pattern.compile(".*/login.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/signin.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/sign-in.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/auth.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/authenticate.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/token.*", Pattern.CASE_INSENSITIVE)
    );

    // Common token field names in JSON responses
    private static final List<String> TOKEN_FIELDS = List.of(
        "token", "accessToken", "access_token", "authToken", "auth_token",
        "jwt", "bearerToken", "bearer_token", "idToken", "id_token"
    );

    public AuthenticationHelper(HttpClient httpClient, String baseUrl) {
        this.httpClient = Objects.requireNonNull(httpClient);
        this.baseUrl = Objects.requireNonNull(baseUrl);
    }

    /**
     * Попытаться автоматически аутентифицироваться, найдя и используя эндпоинты аутентификации.
     * Метод последовательно пытается различные стратегии аутентификации.
     *
     * @param endpoints список эндпоинтов API
     * @return учетные данные в случае успеха, пустой Optional в противном случае
     */
    public Optional<AuthCredentials> attemptAutoAuth(List<ApiEndpoint> endpoints) {
        logger.info("Attempting automatic authentication...");

        // Find authentication endpoints
        ApiEndpoint registerEndpoint = findEndpoint(endpoints, REGISTER_PATTERNS);
        ApiEndpoint loginEndpoint = findEndpoint(endpoints, LOGIN_PATTERNS);

        if (registerEndpoint != null) {
            logger.info("Found registration endpoint: " + registerEndpoint.getPath());
        }
        if (loginEndpoint != null) {
            logger.info("Found login endpoint: " + loginEndpoint.getPath());
        }

        // Try OAuth2 client credentials flow (for banking APIs)
        if (loginEndpoint != null && loginEndpoint.getPath().contains("token")) {
            Optional<AuthCredentials> credentials = tryClientCredentialsFlow(loginEndpoint);
            if (credentials.isPresent()) {
                logger.info("Successfully authenticated via client credentials flow");
                return credentials;
            }
        }

        // Try registration first, then login
        if (registerEndpoint != null) {
            Optional<AuthCredentials> credentials = tryRegisterAndLogin(registerEndpoint, loginEndpoint);
            if (credentials.isPresent()) {
                logger.info("Successfully authenticated via registration");
                return credentials;
            }
        }

        // Try login with default credentials
        if (loginEndpoint != null) {
            Optional<AuthCredentials> credentials = tryLoginWithDefaults(loginEndpoint);
            if (credentials.isPresent()) {
                logger.info("Successfully authenticated with default credentials");
                return credentials;
            }
        }

        logger.warning("Auto-authentication failed. Protected endpoints may not be testable.");
        return Optional.empty();
    }

    /**
     * Создать несколько тестовых пользователей для тестирования (полезно для BOLA тестов).
     * Каждый пользователь создается с уникальным именем и временной меткой.
     *
     * @param endpoints список эндпоинтов API
     * @param count количество пользователей для создания
     * @return список созданных учетных данных
     */
    public List<AuthCredentials> createTestUsers(List<ApiEndpoint> endpoints, int count) {
        List<AuthCredentials> users = new ArrayList<>();

        ApiEndpoint registerEndpoint = findEndpoint(endpoints, REGISTER_PATTERNS);
        ApiEndpoint loginEndpoint = findEndpoint(endpoints, LOGIN_PATTERNS);

        if (registerEndpoint == null) {
            logger.warning("No registration endpoint found, cannot create test users");
            return users;
        }

        for (int i = 1; i <= count; i++) {
            String username = "testuser" + i + "_" + System.currentTimeMillis();
            String password = "TestPass123!";
            String email = username + "@test.local";

            Optional<AuthCredentials> creds = registerUser(registerEndpoint, loginEndpoint,
                username, password, email);
            creds.ifPresent(users::add);
        }

        logger.info("Created " + users.size() + " test users");
        return users;
    }

    private ApiEndpoint findEndpoint(List<ApiEndpoint> endpoints, List<Pattern> patterns) {
        for (ApiEndpoint endpoint : endpoints) {
            String path = endpoint.getPath();
            for (Pattern pattern : patterns) {
                if (pattern.matcher(path).matches()) {
                    // Prefer POST methods for auth endpoints
                    if (endpoint.getMethod().equals("POST")) {
                        return endpoint;
                    }
                }
            }
        }
        return null;
    }

    private Optional<AuthCredentials> tryRegisterAndLogin(
            ApiEndpoint registerEndpoint,
            ApiEndpoint loginEndpoint) {

        String username = "testuser_" + System.currentTimeMillis();
        String password = "TestPassword123!";
        String email = username + "@test.local";

        return registerUser(registerEndpoint, loginEndpoint, username, password, email);
    }

    private Optional<AuthCredentials> registerUser(
            ApiEndpoint registerEndpoint,
            ApiEndpoint loginEndpoint,
            String username,
            String password,
            String email) {

        try {
            // Try registration
            Map<String, Object> registerBody = new HashMap<>();
            registerBody.put("username", username);
            registerBody.put("password", password);
            registerBody.put("email", email);

            String jsonBody = mapper.writeValueAsString(registerBody);

            TestRequest registerRequest = TestRequest.builder()
                .url(baseUrl + registerEndpoint.getPath())
                .method("POST")
                .addHeader("Content-Type", "application/json")
                .body(jsonBody)
                .build();

            TestResponse registerResponse = httpClient.execute(registerRequest);

            // Check if registration succeeded (2xx status)
            if (registerResponse.getStatusCode() >= 200 && registerResponse.getStatusCode() < 300) {
                logger.info("User registered successfully: " + username);

                // Try to extract token from registration response
                String token = extractToken(registerResponse.getBody());
                if (token != null) {
                    return Optional.of(AuthCredentials.builder()
                        .username(username)
                        .password(password)
                        .email(email)
                        .token(token)
                        .build());
                }

                // If no token in registration, try login
                if (loginEndpoint != null) {
                    return tryLogin(loginEndpoint, username, password, email);
                }
            } else {
                logger.fine("Registration failed with status: " + registerResponse.getStatusCode());
            }

        } catch (Exception e) {
            logger.warning("Registration attempt failed: " + e.getMessage());
        }

        return Optional.empty();
    }

    private Optional<AuthCredentials> tryLoginWithDefaults(ApiEndpoint loginEndpoint) {
        // Try common default credentials
        List<Map.Entry<String, String>> defaultCreds = List.of(
            Map.entry("admin", "admin"),
            Map.entry("admin", "password"),
            Map.entry("test", "test"),
            Map.entry("user", "user"),
            Map.entry("demo", "demo")
        );

        for (Map.Entry<String, String> cred : defaultCreds) {
            Optional<AuthCredentials> result = tryLogin(
                loginEndpoint,
                cred.getKey(),
                cred.getValue(),
                cred.getKey() + "@test.local"
            );
            if (result.isPresent()) {
                return result;
            }
        }

        return Optional.empty();
    }

    /**
     * Попытаться использовать OAuth2 Client Credentials Flow (для банковских/финтех API).
     * Этот поток использует client_id и client_secret как параметры запроса вместо JSON тела.
     *
     * @param tokenEndpoint эндпоинт получения токена
     * @return учетные данные с токеном в случае успеха
     */
    private Optional<AuthCredentials> tryClientCredentialsFlow(ApiEndpoint tokenEndpoint) {
        // Common test client credentials for hackathons/sandbox environments
        List<Map.Entry<String, String>> testClientCreds = List.of(
            Map.entry("team200", "5OAaa4DYzYKfnOU6zbR34ic5qMm7VSMB"),
            Map.entry("team100", "test_secret_123"),
            Map.entry("test_client", "test_secret"),
            Map.entry("demo_client", "demo_secret")
        );

        for (Map.Entry<String, String> cred : testClientCreds) {
            Optional<AuthCredentials> result = authenticateWithClientCredentials(
                tokenEndpoint, cred.getKey(), cred.getValue());
            if (result.isPresent()) {
                return result;
            }
        }

        return Optional.empty();
    }

    /**
     * Аутентифицировать конкретного клиента используя OAuth2 Client Credentials Flow.
     * Отправляет запрос с client_id и client_secret для получения токена доступа.
     *
     * @param tokenEndpoint эндпоинт для получения токена
     * @param clientId идентификатор клиента
     * @param clientSecret секрет клиента
     * @return учетные данные с токеном в случае успеха, пустой Optional в противном случае
     */
    public Optional<AuthCredentials> authenticateWithClientCredentials(
            ApiEndpoint tokenEndpoint,
            String clientId,
            String clientSecret) {

        try {
            // Build URL with query parameters
            String url = baseUrl + tokenEndpoint.getPath()
                + "?client_id=" + clientId
                + "&client_secret=" + clientSecret;

            TestRequest tokenRequest = TestRequest.builder()
                .url(url)
                .method("POST")
                .addHeader("Content-Type", "application/x-www-form-urlencoded")
                .build();

            TestResponse tokenResponse = httpClient.execute(tokenRequest);

            if (tokenResponse.getStatusCode() >= 200 && tokenResponse.getStatusCode() < 300) {
                String token = extractToken(tokenResponse.getBody());
                if (token != null) {
                    logger.info("Client credentials flow successful for: " + clientId);
                    return Optional.of(AuthCredentials.builder()
                        .addHeader("X-Client-Id", clientId)
                        .token(token)
                        .build());
                }
            } else {
                logger.fine("Client credentials auth failed for " + clientId +
                    ": HTTP " + tokenResponse.getStatusCode());
            }

        } catch (Exception e) {
            logger.fine("Client credentials attempt failed for " + clientId + ": " + e.getMessage());
        }

        return Optional.empty();
    }

    private Optional<AuthCredentials> tryLogin(
            ApiEndpoint loginEndpoint,
            String username,
            String password,
            String email) {

        try {
            Map<String, Object> loginBody = new HashMap<>();
            loginBody.put("username", username);
            loginBody.put("password", password);

            String jsonBody = mapper.writeValueAsString(loginBody);

            TestRequest loginRequest = TestRequest.builder()
                .url(baseUrl + loginEndpoint.getPath())
                .method("POST")
                .addHeader("Content-Type", "application/json")
                .body(jsonBody)
                .build();

            TestResponse loginResponse = httpClient.execute(loginRequest);

            if (loginResponse.getStatusCode() >= 200 && loginResponse.getStatusCode() < 300) {
                String token = extractToken(loginResponse.getBody());
                if (token != null) {
                    logger.info("Login successful for user: " + username);
                    return Optional.of(AuthCredentials.builder()
                        .username(username)
                        .password(password)
                        .email(email)
                        .token(token)
                        .build());
                }
            }

        } catch (Exception e) {
            logger.fine("Login attempt failed: " + e.getMessage());
        }

        return Optional.empty();
    }

    /**
     * Извлечь токен аутентификации из JSON ответа.
     * Проверяет распространенные имена полей токенов в различных местах JSON структуры.
     *
     * @param responseBody тело JSON ответа
     * @return токен или null, если не найден
     */
    private String extractToken(String responseBody) {
        if (responseBody == null || responseBody.isEmpty()) {
            return null;
        }

        try {
            JsonNode root = mapper.readTree(responseBody);

            // Try common token field names
            for (String fieldName : TOKEN_FIELDS) {
                JsonNode tokenNode = root.get(fieldName);
                if (tokenNode != null && tokenNode.isTextual()) {
                    String token = tokenNode.asText();
                    if (!token.isEmpty()) {
                        return token;
                    }
                }
            }

            // Try nested in "data" object
            JsonNode dataNode = root.get("data");
            if (dataNode != null) {
                for (String fieldName : TOKEN_FIELDS) {
                    JsonNode tokenNode = dataNode.get(fieldName);
                    if (tokenNode != null && tokenNode.isTextual()) {
                        return tokenNode.asText();
                    }
                }
            }

            // Try nested in "user" object
            JsonNode userNode = root.get("user");
            if (userNode != null) {
                for (String fieldName : TOKEN_FIELDS) {
                    JsonNode tokenNode = userNode.get(fieldName);
                    if (tokenNode != null && tokenNode.isTextual()) {
                        return tokenNode.asText();
                    }
                }
            }

        } catch (Exception e) {
            logger.fine("Failed to parse token from response: " + e.getMessage());
        }

        return null;
    }
}
