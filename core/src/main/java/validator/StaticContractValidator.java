package validator;

import io.swagger.v3.oas.models.OpenAPI;
import model.OperationSpec;
import model.Severity;
import model.ValidationFinding;
import parser.SpecNormalizer;
import util.ValidationUtils;

import java.util.*;

/**
 * Enhanced static contract validator with comprehensive checks.
 */
public final class StaticContractValidator implements ContractValidator {

    private final OpenAPI openAPI;

    public StaticContractValidator(OpenAPI openAPI) {
        this.openAPI = Objects.requireNonNull(openAPI, "OpenAPI cannot be null");
    }

    @Override
    public List<ValidationFinding> validate() {
        List<ValidationFinding> findings = new ArrayList<>();

        SpecNormalizer normalizer = new SpecNormalizer();
        List<OperationSpec> operations = normalizer.normalize(openAPI);

        for (OperationSpec op : operations) {
            findings.addAll(validateOperation(op));
        }

        findings.addAll(validateGlobalSpec());

        return findings;
    }

    private List<ValidationFinding> validateOperation(OperationSpec op) {
        List<ValidationFinding> findings = new ArrayList<>();

        // Check for missing operation ID
        if (op.getOperationId() == null || op.getOperationId().isBlank()) {
            findings.add(new ValidationFinding(
                Severity.MEDIUM,
                ValidationFinding.FindingCategory.BEST_PRACTICE,
                "MISSING_OPERATION_ID",
                op.getPath(),
                op.getMethod(),
                "Operation does not have an operationId. This makes it harder to reference and track.",
                "Add an operationId to uniquely identify this operation.",
                null
            ));
        }

        // Check for missing summary or description
        if ((op.getSummary() == null || op.getSummary().isBlank()) &&
            (op.getDescription() == null || op.getDescription().isBlank())) {
            findings.add(new ValidationFinding(
                Severity.LOW,
                ValidationFinding.FindingCategory.DOCUMENTATION,
                "MISSING_OPERATION_DOCUMENTATION",
                op.getPath(),
                op.getMethod(),
                "Operation lacks both summary and description.",
                "Add a summary and/or description to document the operation's purpose.",
                null
            ));
        }

        // Check for deprecated operations
        if (op.isDeprecated()) {
            findings.add(new ValidationFinding(
                Severity.INFO,
                ValidationFinding.FindingCategory.COMPLIANCE,
                "DEPRECATED_OPERATION",
                op.getPath(),
                op.getMethod(),
                "This operation is marked as deprecated.",
                "Consider migrating clients to a newer version of this endpoint.",
                Map.of("deprecated", true)
            ));
        }

        // Check for missing 2xx response
        if (!op.hasSuccessResponse()) {
            findings.add(new ValidationFinding(
                Severity.HIGH,
                ValidationFinding.FindingCategory.CONTRACT,
                "MISSING_SUCCESS_RESPONSE",
                op.getPath(),
                op.getMethod(),
                "Operation has no 2xx (success) response defined.",
                "Add at least one 2xx response to document successful API behavior.",
                null
            ));
        }

        // Check for missing error responses
        if (!op.hasErrorHandling()) {
            findings.add(new ValidationFinding(
                Severity.LOW,
                ValidationFinding.FindingCategory.BEST_PRACTICE,
                "MISSING_ERROR_RESPONSES",
                op.getPath(),
                op.getMethod(),
                "Operation does not define any 4xx or 5xx error responses.",
                "Document error scenarios with appropriate 4xx and 5xx responses.",
                null
            ));
        }

        findings.addAll(validateResponseSchemas(op));

        findings.addAll(validateRequestBody(op));

        findings.addAll(validateParameters(op));

        findings.addAll(validateSecurity(op));

        return findings;
    }

    private List<ValidationFinding> validateResponseSchemas(OperationSpec op) {
        List<ValidationFinding> findings = new ArrayList<>();
        Map<String, ?> responses = op.getResponsesByCode();

        for (String code : responses.keySet()) {
            if (code == null) continue;

            // Only check 2xx responses for schema presence
            if (ValidationUtils.is2xxStatusCode(code)) {
                Object schemaNode = responses.get(code);

                if (schemaNode == null) {
                    findings.add(new ValidationFinding(
                        Severity.HIGH,
                        ValidationFinding.FindingCategory.CONTRACT,
                        "MISSING_RESPONSE_SCHEMA",
                        op.getPath(),
                        op.getMethod(),
                        String.format("Success response %s has no schema defined.", code),
                        "Provide a JSON schema for the response body.",
                        Map.of("statusCode", code)
                    ));
                } else {
                    String schemaText = schemaNode.toString();

                    // Check schema quality
                    if (!ValidationUtils.hasWellDefinedSchema((com.fasterxml.jackson.databind.JsonNode) schemaNode)) {
                        findings.add(new ValidationFinding(
                            Severity.MEDIUM,
                            ValidationFinding.FindingCategory.CONTRACT,
                            "AMBIGUOUS_RESPONSE_SCHEMA",
                            op.getPath(),
                            op.getMethod(),
                            String.format("Response schema for %s lacks explicit 'type' or 'properties'.", code),
                            "Define explicit schema type and properties for clarity.",
                            Map.of("statusCode", code, "schema", ValidationUtils.truncate(schemaText, 100))
                        ));
                    }

                    // Check array schemas
                    if (ValidationUtils.isArraySchema((com.fasterxml.jackson.databind.JsonNode) schemaNode) &&
                        !ValidationUtils.hasItemsDefinition((com.fasterxml.jackson.databind.JsonNode) schemaNode)) {
                        findings.add(new ValidationFinding(
                            Severity.MEDIUM,
                            ValidationFinding.FindingCategory.CONTRACT,
                            "ARRAY_SCHEMA_MISSING_ITEMS",
                            op.getPath(),
                            op.getMethod(),
                            String.format("Array response schema for %s lacks 'items' definition.", code),
                            "Define 'items' schema for array responses.",
                            Map.of("statusCode", code)
                        ));
                    }
                }
            }
        }

        return findings;
    }

    private List<ValidationFinding> validateRequestBody(OperationSpec op) {
        List<ValidationFinding> findings = new ArrayList<>();

        op.getRequestBodySchema().ifPresent(schema -> {
            if (!ValidationUtils.hasWellDefinedSchema(schema)) {
                findings.add(new ValidationFinding(
                    Severity.MEDIUM,
                    ValidationFinding.FindingCategory.CONTRACT,
                    "AMBIGUOUS_REQUEST_SCHEMA",
                    op.getPath(),
                    op.getMethod(),
                    "Request body schema lacks explicit 'type' or 'properties'.",
                    "Define clear request schema with types and properties.",
                    null
                ));
            }
        });

        // Check if mutation operations have request bodies
        if (op.getMethod().matches("POST|PUT|PATCH") && op.getRequestBodySchema().isEmpty()) {
            findings.add(new ValidationFinding(
                Severity.LOW,
                ValidationFinding.FindingCategory.BEST_PRACTICE,
                "MISSING_REQUEST_BODY",
                op.getPath(),
                op.getMethod(),
                "Mutation operation lacks a request body schema.",
                "Consider documenting the request body schema if this operation accepts data.",
                null
            ));
        }

        return findings;
    }

    private List<ValidationFinding> validateParameters(OperationSpec op) {
        List<ValidationFinding> findings = new ArrayList<>();

        // Check if path has parameters but operation doesn't define them
        if (ValidationUtils.hasPathParameters(op.getPath())) {
            List<String> pathParamNames = ValidationUtils.extractPathParameterNames(op.getPath());
            List<String> definedPathParams = op.getParameters().stream()
                .filter(p -> p.getLocation() == model.ParameterSpec.ParameterLocation.PATH)
                .map(model.ParameterSpec::getName)
                .toList();

            for (String paramName : pathParamNames) {
                if (!definedPathParams.contains(paramName)) {
                    findings.add(new ValidationFinding(
                        Severity.HIGH,
                        ValidationFinding.FindingCategory.CONTRACT,
                        "UNDEFINED_PATH_PARAMETER",
                        op.getPath(),
                        op.getMethod(),
                        String.format("Path parameter '{%s}' is not defined in parameters list.", paramName),
                        "Define all path parameters in the operation's parameters section.",
                        Map.of("parameterName", paramName)
                    ));
                }
            }
        }

        return findings;
    }

    private List<ValidationFinding> validateSecurity(OperationSpec op) {
        List<ValidationFinding> findings = new ArrayList<>();

        // Check if mutation operations require authentication
        if (op.getMethod().matches("POST|PUT|PATCH|DELETE") && !op.requiresAuthentication()) {
            findings.add(new ValidationFinding(
                Severity.MEDIUM,
                ValidationFinding.FindingCategory.SECURITY,
                "UNAUTHENTICATED_MUTATION",
                op.getPath(),
                op.getMethod(),
                "Mutation operation does not require authentication.",
                "Consider adding security requirements to prevent unauthorized modifications.",
                null
            ));
        }

        return findings;
    }

    private List<ValidationFinding> validateGlobalSpec() {
        List<ValidationFinding> findings = new ArrayList<>();

        // Check for security schemes definition
        if (openAPI.getComponents() == null || openAPI.getComponents().getSecuritySchemes() == null ||
            openAPI.getComponents().getSecuritySchemes().isEmpty()) {
            findings.add(new ValidationFinding(
                Severity.MEDIUM,
                ValidationFinding.FindingCategory.SECURITY,
                "NO_SECURITY_SCHEMES",
                null,
                null,
                "API specification defines no security schemes.",
                "Define security schemes (OAuth2, API Key, etc.) in components/securitySchemes.",
                null
            ));
        }

        // Check for API description
        if (openAPI.getInfo() != null &&
            (openAPI.getInfo().getDescription() == null || openAPI.getInfo().getDescription().isBlank())) {
            findings.add(new ValidationFinding(
                Severity.LOW,
                ValidationFinding.FindingCategory.DOCUMENTATION,
                "MISSING_API_DESCRIPTION",
                null,
                null,
                "API specification lacks a description.",
                "Add a description in the 'info' section to document the API's purpose.",
                null
            ));
        }

        return findings;
    }
}
