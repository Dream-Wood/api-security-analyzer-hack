package webui.model;

/**
 * Учетные данные пользователя для тестирования множественных учетных записей.
 * Используется для тестирования горизонтального повышения привилегий (BOLA).
 */
public record UserCredentials(
    String username,
    String password,
    String clientId,       // For OAuth/API key scenarios
    String clientSecret,   // For OAuth/API key scenarios
    String token,          // Pre-obtained access token
    String role            // User role (e.g., "user", "admin", "viewer")
) {
    public UserCredentials {
        // Validation: at least one authentication method must be provided
        if ((username == null || username.isEmpty()) &&
            (clientId == null || clientId.isEmpty()) &&
            (token == null || token.isEmpty())) {
            throw new IllegalArgumentException(
                "At least one authentication method must be provided: username/password, clientId/secret, or token"
            );
        }
    }

    /**
     * Проверка, используются ли учетные данные username/password.
     */
    public boolean hasUsernamePassword() {
        return username != null && !username.isEmpty() && password != null && !password.isEmpty();
    }

    /**
     * Проверка, используются ли клиентские учетные данные (OAuth/API key).
     */
    public boolean hasClientCredentials() {
        return clientId != null && !clientId.isEmpty();
    }

    /**
     * Проверка наличия предварительно полученного токена.
     */
    public boolean hasToken() {
        return token != null && !token.isEmpty();
    }

    /**
     * Получение отображаемого имени для логирования и UI.
     */
    public String getDisplayName() {
        if (username != null && !username.isEmpty()) {
            return username;
        }
        if (clientId != null && !clientId.isEmpty()) {
            return "Client: " + clientId;
        }
        return "Token user";
    }
}
