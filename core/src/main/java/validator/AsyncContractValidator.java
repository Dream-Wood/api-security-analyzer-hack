package validator;

import com.fasterxml.jackson.databind.JsonNode;
import model.*;
import parser.AsyncSpecNormalizer;

import java.util.ArrayList;
import java.util.List;

/**
 * Validates AsyncAPI specifications for contract issues.
 */
public final class AsyncContractValidator implements ContractValidator {

    private final JsonNode asyncApiNode;
    private final AsyncSpecNormalizer normalizer = new AsyncSpecNormalizer();

    public AsyncContractValidator(JsonNode asyncApiNode) {
        this.asyncApiNode = asyncApiNode;
    }

    @Override
    public List<ValidationFinding> validate() {
        List<ValidationFinding> findings = new ArrayList<>();

        // Check for missing info section
        findings.addAll(validateInfo());

        // Normalize channels
        List<ChannelSpec> channels = normalizer.normalize(asyncApiNode);

        // Validate each channel
        for (ChannelSpec channel : channels) {
            findings.addAll(validateChannel(channel));
        }

        // Check for empty channels
        if (channels.isEmpty()) {
            findings.add(ValidationFinding.builder()
                .severity(Severity.HIGH)
                .category(ValidationFinding.FindingCategory.CONTRACT)
                .type("EMPTY_CHANNELS")
                .path("channels")
                .method(null)
                .details("AsyncAPI specification has no channels defined")
                .recommendation("Define at least one channel with publish or subscribe operations")
                .build());
        }

        // Validate servers
        findings.addAll(validateServers());

        return findings;
    }

    private List<ValidationFinding> validateInfo() {
        List<ValidationFinding> findings = new ArrayList<>();

        if (!asyncApiNode.has("info")) {
            findings.add(ValidationFinding.builder()
                .severity(Severity.HIGH)
                .category(ValidationFinding.FindingCategory.DOCUMENTATION)
                .type("MISSING_INFO")
                .path("info")
                .method(null)
                .details("AsyncAPI specification missing 'info' section")
                .recommendation("Add 'info' section with title, version, and description")
                .build());
        } else {
            JsonNode infoNode = asyncApiNode.get("info");

            if (!infoNode.has("title") || infoNode.get("title").asText().isBlank()) {
                findings.add(ValidationFinding.builder()
                    .severity(Severity.MEDIUM)
                    .category(ValidationFinding.FindingCategory.DOCUMENTATION)
                    .type("MISSING_API_TITLE")
                    .path("info.title")
                    .method(null)
                    .details("API specification missing title")
                    .recommendation("Add a descriptive title to the info section")
                    .build());
            }

            if (!infoNode.has("version") || infoNode.get("version").asText().isBlank()) {
                findings.add(ValidationFinding.builder()
                    .severity(Severity.MEDIUM)
                    .category(ValidationFinding.FindingCategory.DOCUMENTATION)
                    .type("MISSING_API_VERSION")
                    .path("info.version")
                    .method(null)
                    .details("API specification missing version")
                    .recommendation("Add a version to the info section")
                    .build());
            }

            if (!infoNode.has("description") || infoNode.get("description").asText().isBlank()) {
                findings.add(ValidationFinding.builder()
                    .severity(Severity.LOW)
                    .category(ValidationFinding.FindingCategory.DOCUMENTATION)
                    .type("MISSING_API_DESCRIPTION")
                    .path("info.description")
                    .method(null)
                    .details("API specification missing description")
                    .recommendation("Add a description to explain the purpose of this API")
                    .build());
            }
        }

        return findings;
    }

    private List<ValidationFinding> validateChannel(ChannelSpec channel) {
        List<ValidationFinding> findings = new ArrayList<>();

        // Check if channel has any operations
        if (!channel.hasPublishOperation() && !channel.hasSubscribeOperation()) {
            findings.add(ValidationFinding.builder()
                .severity(Severity.HIGH)
                .category(ValidationFinding.FindingCategory.CONTRACT)
                .type("CHANNEL_NO_OPERATIONS")
                .path("channels." + channel.getName())
                .method(null)
                .details("Channel '" + channel.getName() + "' has no publish or subscribe operations")
                .recommendation("Add at least one operation (publish or subscribe) to the channel")
                .build());
        }

        // Validate publish operation
        if (channel.hasPublishOperation()) {
            findings.addAll(validateOperation(channel.getName(), channel.getPublishOperation().get()));
        }

        // Validate subscribe operation
        if (channel.hasSubscribeOperation()) {
            findings.addAll(validateOperation(channel.getName(), channel.getSubscribeOperation().get()));
        }

        return findings;
    }

    private List<ValidationFinding> validateOperation(String channelName, AsyncOperationSpec operation) {
        List<ValidationFinding> findings = new ArrayList<>();

        // Check for missing operation ID
        if (operation.getOperationId() == null || operation.getOperationId().isBlank()) {
            findings.add(ValidationFinding.builder()
                .severity(Severity.LOW)
                .category(ValidationFinding.FindingCategory.DOCUMENTATION)
                .type("MISSING_OPERATION_ID")
                .path("channels." + channelName + "." + operation.getOperationType().getValue())
                .method(operation.getOperationType().getValue())
                .details("Operation '" + operation.getOperationType() + "' on channel '" +
                    channelName + "' is missing operationId")
                .recommendation("Add an operationId to uniquely identify this operation")
                .build());
        }

        // Check for missing summary
        if (operation.getSummary() == null || operation.getSummary().isBlank()) {
            findings.add(ValidationFinding.builder()
                .severity(Severity.LOW)
                .category(ValidationFinding.FindingCategory.DOCUMENTATION)
                .type("MISSING_OPERATION_SUMMARY")
                .path("channels." + channelName + "." + operation.getOperationType().getValue())
                .method(operation.getOperationType().getValue())
                .details("Operation '" + operation.getOperationType() + "' on channel '" +
                    channelName + "' is missing summary")
                .recommendation("Add a summary to describe what this operation does")
                .build());
        }

        // Check for missing messages
        if (!operation.hasMessages() || operation.getMessages().isEmpty()) {
            findings.add(ValidationFinding.builder()
                .severity(Severity.HIGH)
                .category(ValidationFinding.FindingCategory.CONTRACT)
                .type("MISSING_MESSAGE_DEFINITION")
                .path("channels." + channelName + "." + operation.getOperationType().getValue() + ".message")
                .method(operation.getOperationType().getValue())
                .details("Operation '" + operation.getOperationType() + "' on channel '" +
                    channelName + "' has no message definition")
                .recommendation("Define at least one message for this operation")
                .build());
        } else {
            // Validate messages
            for (MessageSpec message : operation.getMessages()) {
                findings.addAll(validateMessage(channelName, operation.getOperationType().getValue(), message));
            }
        }

        return findings;
    }

    private List<ValidationFinding> validateMessage(String channelName, String operationType, MessageSpec message) {
        List<ValidationFinding> findings = new ArrayList<>();

        // Check for missing payload schema
        if (!message.hasPayloadSchema()) {
            findings.add(ValidationFinding.builder()
                .severity(Severity.MEDIUM)
                .category(ValidationFinding.FindingCategory.CONTRACT)
                .type("MISSING_MESSAGE_PAYLOAD_SCHEMA")
                .path("channels." + channelName + "." + operationType + ".message")
                .method(operationType)
                .details("Message in operation '" + operationType + "' on channel '" +
                    channelName + "' is missing payload schema")
                .recommendation("Define a payload schema to specify the message structure")
                .build());
        } else {
            // Check if payload schema is ambiguous
            JsonNode payloadSchema = message.getPayloadSchema().get();
            if (isAmbiguousSchema(payloadSchema)) {
                findings.add(ValidationFinding.builder()
                    .severity(Severity.MEDIUM)
                    .category(ValidationFinding.FindingCategory.CONTRACT)
                    .type("AMBIGUOUS_MESSAGE_SCHEMA")
                    .path("channels." + channelName + "." + operationType + ".message.payload")
                    .method(operationType)
                    .details("Message payload schema is ambiguous (no type, properties, or $ref)")
                    .recommendation("Specify a clear schema with type and properties or use $ref")
                    .build());
            }
        }

        // Check for missing title or name
        if ((message.getTitle() == null || message.getTitle().isBlank()) &&
            (message.getName() == null || message.getName().isBlank())) {
            findings.add(ValidationFinding.builder()
                .severity(Severity.LOW)
                .category(ValidationFinding.FindingCategory.DOCUMENTATION)
                .type("MISSING_MESSAGE_TITLE")
                .path("channels." + channelName + "." + operationType + ".message")
                .method(operationType)
                .details("Message is missing both 'name' and 'title'")
                .recommendation("Add a name or title to identify the message")
                .build());
        }

        return findings;
    }

    private List<ValidationFinding> validateServers() {
        List<ValidationFinding> findings = new ArrayList<>();

        if (!asyncApiNode.has("servers") || asyncApiNode.get("servers").size() == 0) {
            findings.add(ValidationFinding.builder()
                .severity(Severity.MEDIUM)
                .category(ValidationFinding.FindingCategory.COMPLIANCE)
                .type("NO_SERVERS_DEFINED")
                .path("servers")
                .method(null)
                .details("AsyncAPI specification has no servers defined")
                .recommendation("Define at least one server to specify where the API is hosted")
                .build());
        }

        return findings;
    }

    private boolean isAmbiguousSchema(JsonNode schema) {
        if (schema == null) {
            return true;
        }

        // Check for $ref (not ambiguous if ref is present)
        if (schema.has("$ref")) {
            return false;
        }

        // Check for type
        if (schema.has("type")) {
            String type = schema.get("type").asText();
            if ("object".equals(type)) {
                // Object should have properties
                return !schema.has("properties") && !schema.has("additionalProperties");
            }
            return false; // Has type, not ambiguous
        }

        // Check for allOf, anyOf, oneOf
        if (schema.has("allOf") || schema.has("anyOf") || schema.has("oneOf")) {
            return false;
        }

        // No type, no ref, no composition - ambiguous
        return true;
    }
}
