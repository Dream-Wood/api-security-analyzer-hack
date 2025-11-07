package cli;

import io.swagger.v3.oas.models.OpenAPI;
import model.ValidationFinding;
import parser.OpenApiLoader;
import validator.StaticContractValidator;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Сервисный класс для загрузки и валидации OpenAPI спецификаций.
 * Корректно обрабатывает как валидные, так и невалидные/неполные спецификации.
 *
 * <p>Класс выполняет следующие операции:
 * <ul>
 *   <li>Загрузка OpenAPI спецификации из файла или URL</li>
 *   <li>Парсинг и валидация структуры спецификации</li>
 *   <li>Статическая валидация контракта API</li>
 *   <li>Сбор и возврат всех найденных проблем</li>
 * </ul>
 *
 * @author API Security Analyzer Team
 * @since 1.0
 */
public final class SpecAnalyzer {

    private final OpenApiLoader loader;

    /**
     * Создает новый экземпляр анализатора спецификаций.
     */
    public SpecAnalyzer() {
        this.loader = new OpenApiLoader();
    }

    /**
     * Результат анализа OpenAPI спецификации.
     * Содержит информацию об успешности операции, сообщениях парсинга и найденных проблемах валидации.
     */
    public static final class AnalysisResult {
        private final boolean successful;
        private final List<String> parsingMessages;
        private final List<ValidationFinding> validationFindings;
        private final String errorMessage;

        private AnalysisResult(boolean successful,
                               List<String> parsingMessages,
                               List<ValidationFinding> validationFindings,
                               String errorMessage) {
            this.successful = successful;
            this.parsingMessages = parsingMessages != null ? List.copyOf(parsingMessages) : List.of();
            this.validationFindings = validationFindings != null ? List.copyOf(validationFindings) : List.of();
            this.errorMessage = errorMessage;
        }

        public static AnalysisResult success(List<String> parsingMessages,
                                           List<ValidationFinding> validationFindings) {
            return new AnalysisResult(true, parsingMessages, validationFindings, null);
        }

        public static AnalysisResult failure(String errorMessage) {
            return new AnalysisResult(false, List.of(), List.of(), errorMessage);
        }

        public boolean isSuccessful() {
            return successful;
        }

        public List<String> getParsingMessages() {
            return parsingMessages;
        }

        public List<ValidationFinding> getValidationFindings() {
            return validationFindings;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public boolean hasParsingMessages() {
            return !parsingMessages.isEmpty();
        }

        public boolean hasValidationFindings() {
            return !validationFindings.isEmpty();
        }
    }

    /**
     * Анализирует OpenAPI спецификацию из файла или URL.
     *
     * <p>Метод выполняет следующие шаги:
     * <ol>
     *   <li>Загрузка спецификации из указанного источника</li>
     *   <li>Парсинг и проверка корректности структуры</li>
     *   <li>Статическая валидация контракта API</li>
     * </ol>
     *
     * @param location путь к файлу (YAML/JSON) или URL OpenAPI спецификации
     * @return результат анализа, содержащий сообщения парсинга и найденные проблемы валидации
     */
    public AnalysisResult analyze(String location) {
        Objects.requireNonNull(location, "location must not be null");

        // Step 1: Load the specification
        OpenApiLoader.LoadResult loadResult;
        try {
            loadResult = loader.load(location);
        } catch (Exception e) {
            return AnalysisResult.failure(
                "Failed to load specification: " + e.getMessage()
            );
        }

        // Step 2: Check if specification was parsed successfully
        if (!loadResult.isSuccessful()) {
            // Specification is invalid/incomplete
            StringBuilder errorMsg = new StringBuilder("Failed to parse OpenAPI specification.");
            List<String> messages = loadResult.getMessages();
            if (!messages.isEmpty()) {
                errorMsg.append(" Parsing errors:\n");
                for (String msg : messages) {
                    errorMsg.append("  - ").append(msg).append("\n");
                }
            }
            return AnalysisResult.failure(errorMsg.toString().trim());
        }

        OpenAPI openAPI = loadResult.getOpenAPI();
        List<String> messages = loadResult.getMessages();

        // Step 3: Validate the specification
        List<ValidationFinding> findings = new ArrayList<>();
        try {
            StaticContractValidator validator = new StaticContractValidator(openAPI);
            findings = validator.validate();
        } catch (Exception e) {
            return AnalysisResult.failure(
                "Validation failed: " + e.getMessage()
            );
        }

        return AnalysisResult.success(messages, findings);
    }
}
