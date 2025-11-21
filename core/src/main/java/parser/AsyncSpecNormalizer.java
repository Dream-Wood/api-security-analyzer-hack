package parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import model.*;

import java.util.*;

/**
 * Normalizer that converts AsyncAPI to internal model format.
 */
public final class AsyncSpecNormalizer {

    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Normalizes AsyncAPI specification to list of ChannelSpec objects.
     *
     * @param asyncApiNode the AsyncAPI specification as JsonNode
     * @return list of normalized channels
     */
    public List<ChannelSpec> normalize(JsonNode asyncApiNode) {
        Objects.requireNonNull(asyncApiNode, "asyncApiNode must not be null");

        if (!asyncApiNode.has("channels")) {
            return Collections.emptyList();
        }

        List<ChannelSpec> result = new ArrayList<>();
        JsonNode channelsNode = asyncApiNode.get("channels");

        // Get global security if present
        List<String> globalSecurity = extractGlobalSecurity(asyncApiNode);

        Iterator<Map.Entry<String, JsonNode>> channelIterator = channelsNode.fields();
        while (channelIterator.hasNext()) {
            Map.Entry<String, JsonNode> entry = channelIterator.next();
            String channelName = entry.getKey();
            JsonNode channelNode = entry.getValue();

            ChannelSpec channelSpec = normalizeChannel(channelName, channelNode, globalSecurity);
            result.add(channelSpec);
        }

        return result;
    }

    /**
     * Normalizes AsyncAPI specification and extracts all operations.
     *
     * @param asyncApiNode the AsyncAPI specification as JsonNode
     * @return list of normalized operations
     */
    public List<AsyncOperationSpec> normalizeOperations(JsonNode asyncApiNode) {
        List<ChannelSpec> channels = normalize(asyncApiNode);
        List<AsyncOperationSpec> operations = new ArrayList<>();

        for (ChannelSpec channel : channels) {
            operations.addAll(channel.getAllOperations());
        }

        return operations;
    }

    /**
     * Extracts server specifications from AsyncAPI.
     *
     * @param asyncApiNode the AsyncAPI specification as JsonNode
     * @return map of server specifications
     */
    public Map<String, ServerSpec> extractServers(JsonNode asyncApiNode) {
        if (!asyncApiNode.has("servers")) {
            return Collections.emptyMap();
        }

        Map<String, ServerSpec> servers = new HashMap<>();
        JsonNode serversNode = asyncApiNode.get("servers");

        Iterator<Map.Entry<String, JsonNode>> serverIterator = serversNode.fields();
        while (serverIterator.hasNext()) {
            Map.Entry<String, JsonNode> entry = serverIterator.next();
            String serverName = entry.getKey();
            JsonNode serverNode = entry.getValue();

            ServerSpec serverSpec = normalizeServer(serverName, serverNode);
            servers.put(serverName, serverSpec);
        }

        return servers;
    }

    private ChannelSpec normalizeChannel(String channelName, JsonNode channelNode, List<String> globalSecurity) {
        String description = getTextValue(channelNode, "description");
        List<String> servers = extractChannelServers(channelNode);
        Map<String, Object> bindings = extractBindings(channelNode);
        Map<String, Object> parameters = extractParameters(channelNode);

        // Extract publish operation
        Optional<AsyncOperationSpec> publishOp = Optional.empty();
        if (channelNode.has("publish")) {
            publishOp = Optional.of(normalizeOperation(
                channelName,
                AsyncOperationType.PUBLISH,
                channelNode.get("publish"),
                globalSecurity
            ));
        }

        // Extract subscribe operation
        Optional<AsyncOperationSpec> subscribeOp = Optional.empty();
        if (channelNode.has("subscribe")) {
            subscribeOp = Optional.of(normalizeOperation(
                channelName,
                AsyncOperationType.SUBSCRIBE,
                channelNode.get("subscribe"),
                globalSecurity
            ));
        }

        return ChannelSpec.builder()
            .name(channelName)
            .description(description)
            .publishOperation(publishOp)
            .subscribeOperation(subscribeOp)
            .servers(servers)
            .bindings(bindings)
            .parameters(parameters)
            .build();
    }

    private AsyncOperationSpec normalizeOperation(String channelName, AsyncOperationType operationType,
                                                   JsonNode operationNode, List<String> globalSecurity) {
        String operationId = getTextValue(operationNode, "operationId");
        String summary = getTextValue(operationNode, "summary");
        String description = getTextValue(operationNode, "description");
        List<String> tags = extractTags(operationNode);
        Map<String, Object> bindings = extractBindings(operationNode);

        // Extract messages
        List<MessageSpec> messages = extractMessages(operationNode);

        // Extract security
        List<String> security = extractOperationSecurity(operationNode, globalSecurity);

        return AsyncOperationSpec.builder()
            .channelName(channelName)
            .operationType(operationType)
            .operationId(operationId)
            .summary(summary)
            .description(description)
            .messages(messages)
            .securitySchemes(security)
            .tags(tags)
            .bindings(bindings)
            .build();
    }

    private List<MessageSpec> extractMessages(JsonNode operationNode) {
        List<MessageSpec> messages = new ArrayList<>();

        if (!operationNode.has("message")) {
            return messages;
        }

        JsonNode messageNode = operationNode.get("message");

        // Handle oneOf (multiple messages)
        if (messageNode.has("oneOf")) {
            JsonNode oneOfNode = messageNode.get("oneOf");
            for (JsonNode msgNode : oneOfNode) {
                messages.add(normalizeMessage(msgNode));
            }
        } else {
            // Single message
            messages.add(normalizeMessage(messageNode));
        }

        return messages;
    }

    private MessageSpec normalizeMessage(JsonNode messageNode) {
        String name = getTextValue(messageNode, "name");
        String title = getTextValue(messageNode, "title");
        String summary = getTextValue(messageNode, "summary");
        String description = getTextValue(messageNode, "description");
        String contentType = getTextValue(messageNode, "contentType");
        List<String> tags = extractTags(messageNode);
        Map<String, Object> bindings = extractBindings(messageNode);

        // Extract payload schema
        Optional<JsonNode> payloadSchema = Optional.empty();
        if (messageNode.has("payload")) {
            payloadSchema = Optional.of(messageNode.get("payload"));
        }

        // Extract headers schema
        Optional<JsonNode> headersSchema = Optional.empty();
        if (messageNode.has("headers")) {
            headersSchema = Optional.of(messageNode.get("headers"));
        }

        return MessageSpec.builder()
            .name(name)
            .title(title)
            .summary(summary)
            .description(description)
            .payloadSchema(payloadSchema)
            .headersSchema(headersSchema)
            .contentType(contentType)
            .tags(tags)
            .bindings(bindings)
            .build();
    }

    private ServerSpec normalizeServer(String serverName, JsonNode serverNode) {
        String url = getTextValue(serverNode, "url");
        String protocol = getTextValue(serverNode, "protocol");
        String protocolVersion = getTextValue(serverNode, "protocolVersion");
        String description = getTextValue(serverNode, "description");
        List<String> security = extractServerSecurity(serverNode);
        Map<String, Object> variables = extractVariables(serverNode);
        Map<String, Object> bindings = extractBindings(serverNode);

        return ServerSpec.builder()
            .name(serverName)
            .url(url != null ? url : "")
            .protocol(protocol != null ? protocol : "unknown")
            .protocolVersion(protocolVersion)
            .description(description)
            .securitySchemes(security)
            .variables(variables)
            .bindings(bindings)
            .build();
    }

    private List<String> extractGlobalSecurity(JsonNode asyncApiNode) {
        if (!asyncApiNode.has("security")) {
            return Collections.emptyList();
        }

        List<String> schemes = new ArrayList<>();
        JsonNode securityNode = asyncApiNode.get("security");

        for (JsonNode secItem : securityNode) {
            Iterator<String> fieldNames = secItem.fieldNames();
            while (fieldNames.hasNext()) {
                schemes.add(fieldNames.next());
            }
        }

        return schemes;
    }

    private List<String> extractOperationSecurity(JsonNode operationNode, List<String> globalSecurity) {
        if (operationNode.has("security")) {
            List<String> schemes = new ArrayList<>();
            JsonNode securityNode = operationNode.get("security");

            for (JsonNode secItem : securityNode) {
                Iterator<String> fieldNames = secItem.fieldNames();
                while (fieldNames.hasNext()) {
                    schemes.add(fieldNames.next());
                }
            }
            return schemes;
        }

        return globalSecurity;
    }

    private List<String> extractServerSecurity(JsonNode serverNode) {
        if (!serverNode.has("security")) {
            return Collections.emptyList();
        }

        List<String> schemes = new ArrayList<>();
        JsonNode securityNode = serverNode.get("security");

        for (JsonNode secItem : securityNode) {
            Iterator<String> fieldNames = secItem.fieldNames();
            while (fieldNames.hasNext()) {
                schemes.add(fieldNames.next());
            }
        }

        return schemes;
    }

    private List<String> extractChannelServers(JsonNode channelNode) {
        if (!channelNode.has("servers")) {
            return Collections.emptyList();
        }

        List<String> servers = new ArrayList<>();
        JsonNode serversNode = channelNode.get("servers");

        for (JsonNode serverNode : serversNode) {
            servers.add(serverNode.asText());
        }

        return servers;
    }

    private List<String> extractTags(JsonNode node) {
        if (!node.has("tags")) {
            return Collections.emptyList();
        }

        List<String> tags = new ArrayList<>();
        JsonNode tagsNode = node.get("tags");

        for (JsonNode tagNode : tagsNode) {
            if (tagNode.has("name")) {
                tags.add(tagNode.get("name").asText());
            } else if (tagNode.isTextual()) {
                tags.add(tagNode.asText());
            }
        }

        return tags;
    }

    private Map<String, Object> extractBindings(JsonNode node) {
        if (!node.has("bindings")) {
            return Collections.emptyMap();
        }

        Map<String, Object> bindings = new HashMap<>();
        JsonNode bindingsNode = node.get("bindings");

        Iterator<Map.Entry<String, JsonNode>> fields = bindingsNode.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            bindings.put(entry.getKey(), entry.getValue());
        }

        return bindings;
    }

    private Map<String, Object> extractParameters(JsonNode node) {
        if (!node.has("parameters")) {
            return Collections.emptyMap();
        }

        Map<String, Object> parameters = new HashMap<>();
        JsonNode parametersNode = node.get("parameters");

        Iterator<Map.Entry<String, JsonNode>> fields = parametersNode.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            parameters.put(entry.getKey(), entry.getValue());
        }

        return parameters;
    }

    private Map<String, Object> extractVariables(JsonNode node) {
        if (!node.has("variables")) {
            return Collections.emptyMap();
        }

        Map<String, Object> variables = new HashMap<>();
        JsonNode variablesNode = node.get("variables");

        Iterator<Map.Entry<String, JsonNode>> fields = variablesNode.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            variables.put(entry.getKey(), entry.getValue());
        }

        return variables;
    }

    private String getTextValue(JsonNode node, String fieldName) {
        if (node.has(fieldName)) {
            JsonNode fieldNode = node.get(fieldName);
            if (fieldNode.isTextual()) {
                return fieldNode.asText();
            }
        }
        return null;
    }
}
