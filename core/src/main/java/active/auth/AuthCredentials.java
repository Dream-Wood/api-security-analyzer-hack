package active.auth;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Представляет учетные данные аутентификации для тестового пользователя.
 * Содержит информацию об имени пользователя, пароле, токенах и дополнительных заголовках.
 */
public final class AuthCredentials {
    private final String username;
    private final String password;
    private final String email;
    private final String token;
    private final String refreshToken;
    private final Map<String, String> additionalHeaders;

    private AuthCredentials(Builder builder) {
        this.username = builder.username;
        this.password = builder.password;
        this.email = builder.email;
        this.token = builder.token;
        this.refreshToken = builder.refreshToken;
        this.additionalHeaders = builder.additionalHeaders != null
            ? new HashMap<>(builder.additionalHeaders)
            : new HashMap<>();
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getEmail() {
        return email;
    }

    public String getToken() {
        return token;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public Map<String, String> getAdditionalHeaders() {
        return new HashMap<>(additionalHeaders);
    }

    /**
     * Получить значение заголовка авторизации (Bearer токен или пользовательский формат).
     *
     * @return значение заголовка Authorization или null, если токен отсутствует
     */
    public String getAuthorizationHeader() {
        if (token != null) {
            // Try to detect if token already has Bearer prefix
            if (token.toLowerCase().startsWith("bearer ")) {
                return token;
            }
            return "Bearer " + token;
        }
        return null;
    }

    public boolean hasToken() {
        return token != null && !token.isEmpty();
    }

    @Override
    public String toString() {
        return "AuthCredentials{" +
                "username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", hasToken=" + hasToken() +
                '}';
    }

    public static class Builder {
        private String username;
        private String password;
        private String email;
        private String token;
        private String refreshToken;
        private Map<String, String> additionalHeaders;

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        public Builder password(String password) {
            this.password = password;
            return this;
        }

        public Builder email(String email) {
            this.email = email;
            return this;
        }

        public Builder token(String token) {
            this.token = token;
            return this;
        }

        public Builder refreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }

        public Builder additionalHeaders(Map<String, String> headers) {
            this.additionalHeaders = headers;
            return this;
        }

        public Builder addHeader(String key, String value) {
            if (this.additionalHeaders == null) {
                this.additionalHeaders = new HashMap<>();
            }
            this.additionalHeaders.put(key, value);
            return this;
        }

        public AuthCredentials build() {
            return new AuthCredentials(this);
        }
    }
}
