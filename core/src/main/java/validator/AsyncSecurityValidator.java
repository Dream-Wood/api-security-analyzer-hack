package validator;

import com.fasterxml.jackson.databind.JsonNode;
import model.*;
import parser.AsyncSpecNormalizer;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Validates AsyncAPI specifications for security issues.
 */
public final class AsyncSecurityValidator implements ContractValidator {

    private final JsonNode asyncApiNode;
    private final AsyncSpecNormalizer normalizer = new AsyncSpecNormalizer();

    public AsyncSecurityValidator(JsonNode asyncApiNode) {
        this.asyncApiNode = asyncApiNode;
    }

    @Override
    public List<ValidationFinding> validate() {
        List<ValidationFinding> findings = new ArrayList<>();

        // Check for security schemes
        findings.addAll(validateSecuritySchemes());

        // Validate server security
        findings.addAll(validateServers());

        // Validate channel/operation security
        List<ChannelSpec> channels = normalizer.normalize(asyncApiNode);
        for (ChannelSpec channel : channels) {
            findings.addAll(validateChannelSecurity(channel));
        }

        return findings;
    }

    private List<ValidationFinding> validateSecuritySchemes() {
        List<ValidationFinding> findings = new ArrayList<>();

        if (!asyncApiNode.has("components") ||
            !asyncApiNode.get("components").has("securitySchemes") ||
            asyncApiNode.get("components").get("securitySchemes").size() == 0) {

            findings.add(ValidationFinding.builder()
                .severity(Severity.MEDIUM)
                .category(ValidationFinding.FindingCategory.COMPLIANCE)
                .type("NO_SECURITY_SCHEMES")
                .path("components.securitySchemes")
                .method(null)
                .details("AsyncAPI specification has no security schemes defined")
                .recommendation("Define security schemes to protect your message channels")
                .build());
        } else {
            JsonNode securitySchemes = asyncApiNode.get("components").get("securitySchemes");
            findings.addAll(validateSecuritySchemeDefinitions(securitySchemes));
        }

        return findings;
    }

    private List<ValidationFinding> validateSecuritySchemeDefinitions(JsonNode securitySchemes) {
        List<ValidationFinding> findings = new ArrayList<>();

        Iterator<String> fieldNames = securitySchemes.fieldNames();
        while (fieldNames.hasNext()) {
            String schemeName = fieldNames.next();
            JsonNode schemeNode = securitySchemes.get(schemeName);

            if (!schemeNode.has("type")) {
                findings.add(ValidationFinding.builder()
                    .severity(Severity.HIGH)
                    .category(ValidationFinding.FindingCategory.SECURITY)
                    .type("INVALID_SECURITY_SCHEME")
                    .path("components.securitySchemes." + schemeName)
                    .method(null)
                    .details("Security scheme '" + schemeName + "' is missing 'type' field")
                    .recommendation("Specify the type of security scheme (e.g., httpApiKey, userPassword, X509)")
                    .build());
            } else {
                String type = schemeNode.get("type").asText();

                // Check for insecure schemes
                if ("userPassword".equals(type)) {
                    findings.add(ValidationFinding.builder()
                        .severity(Severity.MEDIUM)
                        .category(ValidationFinding.FindingCategory.SECURITY)
                        .type("BASIC_AUTHENTICATION_USED")
                        .path("components.securitySchemes." + schemeName)
                        .method(null)
                        .details("Security scheme '" + schemeName + "' uses userPassword authentication")
                        .recommendation("Consider using token-based authentication or OAuth2 instead")
                        .build());
                }

                // Check for API keys in plain text (specific to certain protocols)
                if ("httpApiKey".equals(type) && schemeNode.has("in")) {
                    String location = schemeNode.get("in").asText();
                    if ("query".equals(location)) {
                        findings.add(ValidationFinding.builder()
                            .severity(Severity.HIGH)
                            .category(ValidationFinding.FindingCategory.SECURITY)
                            .type("API_KEY_IN_QUERY")
                            .path("components.securitySchemes." + schemeName)
                            .method(null)
                            .details("Security scheme '" + schemeName + "' uses API key in query parameter")
                            .recommendation("API keys in query parameters can be logged. Use headers instead")
                            .build());
                    }
                }
            }
        }

        return findings;
    }

    private List<ValidationFinding> validateServers() {
        List<ValidationFinding> findings = new ArrayList<>();

        if (!asyncApiNode.has("servers")) {
            return findings;
        }

        List<ServerSpec> servers = normalizer.extractServers(asyncApiNode);

        for (ServerSpec server : servers) {
            findings.addAll(validateServer(server));
        }

        return findings;
    }

    private List<ValidationFinding> validateServer(ServerSpec server) {
        List<ValidationFinding> findings = new ArrayList<>();

        // Check if server URL uses secure protocol
        if (!server.isSecure()) {
            String protocol = server.getProtocol().toLowerCase();

            // Check for explicitly insecure protocols
            if (protocol.equals("ws") || protocol.equals("mqtt") || protocol.equals("http") ||
                protocol.equals("amqp") || protocol.equals("kafka")) {

                findings.add(ValidationFinding.builder()
                    .severity(Severity.HIGH)
                    .category(ValidationFinding.FindingCategory.SECURITY)
                    .type("INSECURE_SERVER_PROTOCOL")
                    .path("servers." + server.getName())
                    .method(null)
                    .details("Server '" + server.getName() + "' uses insecure protocol: " + server.getProtocol())
                    .recommendation("Use secure variant: " + getSecureVariant(protocol))
                    .build());
            }
        }

        // Check if server has no security
        if (!server.requiresAuthentication()) {
            findings.add(ValidationFinding.builder()
                .severity(Severity.MEDIUM)
                .category(ValidationFinding.FindingCategory.SECURITY)
                .type("SERVER_NO_AUTHENTICATION")
                .path("servers." + server.getName())
                .method(null)
                .details("Server '" + server.getName() + "' has no authentication requirements")
                .recommendation("Add security requirements to protect access to this server")
                .build());
        }

        return findings;
    }

    private List<ValidationFinding> validateChannelSecurity(ChannelSpec channel) {
        List<ValidationFinding> findings = new ArrayList<>();

        // Check publish operation
        if (channel.hasPublishOperation()) {
            AsyncOperationSpec publishOp = channel.getPublishOperation().get();
            if (!publishOp.requiresAuthentication()) {
                findings.add(ValidationFinding.builder()
                    .severity(Severity.HIGH)
                    .category(ValidationFinding.FindingCategory.SECURITY)
                    .type("UNAUTHENTICATED_PUBLISH_OPERATION")
                    .path("channels." + channel.getName() + ".publish")
                    .method("PUBLISH")
                    .details("Channel '" + channel.getName() + "' allows unauthenticated publish operations")
                    .recommendation("Add security requirements to prevent unauthorized message publishing")
                    .build());
            }
        }

        // Check subscribe operation
        if (channel.hasSubscribeOperation()) {
            AsyncOperationSpec subscribeOp = channel.getSubscribeOperation().get();
            if (!subscribeOp.requiresAuthentication()) {
                // Subscribe without auth is less critical but still a concern for sensitive data
                Severity severity = isSensitiveChannel(channel.getName()) ? Severity.HIGH : Severity.MEDIUM;

                findings.add(ValidationFinding.builder()
                    .severity(severity)
                    .category(ValidationFinding.FindingCategory.SECURITY)
                    .type("UNAUTHENTICATED_SUBSCRIBE_OPERATION")
                    .path("channels." + channel.getName() + ".subscribe")
                    .method("SUBSCRIBE")
                    .details("Channel '" + channel.getName() + "' allows unauthenticated subscribe operations")
                    .recommendation("Add security requirements to control who can receive messages")
                    .build());
            }
        }

        return findings;
    }

    private boolean isSensitiveChannel(String channelName) {
        String lowerName = channelName.toLowerCase();
        return lowerName.contains("user") ||
            lowerName.contains("account") ||
            lowerName.contains("payment") ||
            lowerName.contains("order") ||
            lowerName.contains("private") ||
            lowerName.contains("admin") ||
            lowerName.contains("internal");
    }

    private String getSecureVariant(String protocol) {
        return switch (protocol) {
            case "ws" -> "wss (WebSocket Secure)";
            case "mqtt" -> "mqtts (MQTT over TLS)";
            case "http" -> "https (HTTP over TLS)";
            case "amqp" -> "amqps (AMQP over TLS)";
            case "kafka" -> "kafka-secure (Kafka with SSL/SASL)";
            default -> protocol + " over TLS";
        };
    }
}
