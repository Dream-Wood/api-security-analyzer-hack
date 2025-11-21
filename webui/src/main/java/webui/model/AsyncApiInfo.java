package webui.model;

import java.util.List;

/**
 * Информация об AsyncAPI спецификации для WebUI.
 * Содержит список серверов и доступных протоколов.
 */
public record AsyncApiInfo(
    List<ServerInfo> servers,
    List<String> availableProtocols,
    List<AsyncScannerInfo> asyncScanners,
    List<String> validationMessages,
    boolean valid
) {
    /**
     * Создаёт успешный результат без ошибок валидации.
     */
    public static AsyncApiInfo success(List<ServerInfo> servers, List<String> availableProtocols,
                                        List<AsyncScannerInfo> asyncScanners) {
        return new AsyncApiInfo(servers, availableProtocols, asyncScanners, List.of(), true);
    }

    /**
     * Создаёт успешный результат с предупреждениями.
     */
    public static AsyncApiInfo withWarnings(List<ServerInfo> servers, List<String> availableProtocols,
                                             List<AsyncScannerInfo> asyncScanners, List<String> warnings) {
        return new AsyncApiInfo(servers, availableProtocols, asyncScanners, warnings, true);
    }

    /**
     * Создаёт результат с ошибками валидации (файл не является валидной AsyncAPI спецификацией).
     */
    public static AsyncApiInfo invalid(List<String> errors, List<String> availableProtocols,
                                        List<AsyncScannerInfo> asyncScanners) {
        return new AsyncApiInfo(List.of(), availableProtocols, asyncScanners, errors, false);
    }
}
