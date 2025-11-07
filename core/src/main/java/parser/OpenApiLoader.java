package parser;

import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.ParseOptions;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import io.swagger.v3.oas.models.OpenAPI;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Улучшенный загрузчик спецификаций OpenAPI с расширенной обработкой ошибок.
 *
 * <p>Поддерживает:
 * <ul>
 *   <li>Загрузку из локальных файлов и URL</li>
 *   <li>Полное разрешение ссылок ($ref)</li>
 *   <li>Детальную валидацию с информативными сообщениями об ошибках</li>
 *   <li>Предупреждения о проблемах в спецификации</li>
 * </ul>
 */
public final class OpenApiLoader {

    /**
     * Результат загрузки спецификации OpenAPI.
     * Содержит загруженный объект OpenAPI, сообщения валидации и статус успешности.
     */
    public static final class LoadResult {
        private final OpenAPI openAPI;
        private final List<String> messages;
        private final boolean successful;

        private LoadResult(OpenAPI openAPI, List<String> messages, boolean successful) {
            this.openAPI = openAPI;
            this.messages = messages != null ? List.copyOf(messages) : List.of();
            this.successful = successful;
        }

        public static LoadResult success(OpenAPI openAPI, List<String> messages) {
            return new LoadResult(openAPI, messages, true);
        }

        public static LoadResult failure(List<String> messages) {
            return new LoadResult(null, messages, false);
        }

        public OpenAPI getOpenAPI() {
            return openAPI;
        }

        public List<String> getMessages() {
            return messages;
        }

        public boolean isSuccessful() {
            return successful;
        }

        public boolean hasMessages() {
            return !messages.isEmpty();
        }
    }

    /**
     * Загружает спецификацию OpenAPI из файла или URL.
     *
     * @param location путь к файлу или URL спецификации
     * @return результат загрузки с объектом OpenAPI и сообщениями валидации
     */
    public LoadResult load(String location) {
        Objects.requireNonNull(location, "location must not be null");

        try {
            ParseOptions parseOptions = new ParseOptions();
            parseOptions.setResolve(true);
            parseOptions.setResolveFully(true);

            SwaggerParseResult result = new OpenAPIV3Parser().readLocation(location, null, parseOptions);

            OpenAPI openAPI = result.getOpenAPI();
            List<String> messages = result.getMessages() != null
                ? new ArrayList<>(result.getMessages())
                : new ArrayList<>();

            if (openAPI == null) {
                if (messages.isEmpty()) {
                    messages.add("Failed to parse OpenAPI specification. The file may be invalid or inaccessible.");
                }
                return LoadResult.failure(messages);
            }

            if (openAPI.getInfo() == null) {
                messages.add("Warning: OpenAPI specification missing 'info' section");
            }

            if (openAPI.getPaths() == null || openAPI.getPaths().isEmpty()) {
                messages.add("Warning: OpenAPI specification has no paths defined");
            }

            return LoadResult.success(openAPI, messages);

        } catch (Exception e) {
            List<String> messages = new ArrayList<>();
            messages.add("Exception during parsing: " + e.getMessage());
            return LoadResult.failure(messages);
        }
    }

    /**
     * Проверяет, является ли расположение URL-адресом.
     *
     * @param location проверяемое расположение
     * @return true, если это URL (начинается с http:// или https://)
     */
    public static boolean isUrl(String location) {
        if (location == null) {
            return false;
        }
        String lower = location.toLowerCase();
        return lower.startsWith("http://") || lower.startsWith("https://");
    }
}
