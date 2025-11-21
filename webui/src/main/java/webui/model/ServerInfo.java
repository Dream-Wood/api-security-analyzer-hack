package webui.model;

/**
 * Информация о сервере из AsyncAPI спецификации.
 */
public record ServerInfo(
    String name,
    String url,
    String protocol,
    String protocolVersion,
    String description
) {
}
