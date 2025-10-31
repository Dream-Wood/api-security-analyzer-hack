package validator;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityScheme;
import model.OperationSpec;
import model.Severity;
import model.ValidationFinding;
import parser.SpecNormalizer;

import java.util.*;

/**
 * Security-focused validator that checks for common API security issues.
 */
public final class SecurityValidator implements ContractValidator {

    private final OpenAPI openAPI;

    public SecurityValidator(OpenAPI openAPI) {
        this.openAPI = Objects.requireNonNull(openAPI, "OpenAPI cannot be null");
    }

    @Override
    public List<ValidationFinding> validate() {

        SpecNormalizer normalizer = new SpecNormalizer();
        List<OperationSpec> operations = normalizer.normalize(openAPI);

        List<ValidationFinding> findings = new ArrayList<>(validateGlobalSecurity());

        for (OperationSpec op : operations) {
            findings.addAll(validateOperationSecurity(op));
        }

        return findings;
    }

    private List<ValidationFinding> validateGlobalSecurity() {
        List<ValidationFinding> findings = new ArrayList<>();

        // Check if security schemes are defined
        if (openAPI.getComponents() == null ||
            openAPI.getComponents().getSecuritySchemes() == null ||
            openAPI.getComponents().getSecuritySchemes().isEmpty()) {

            findings.add(new ValidationFinding(
                Severity.HIGH,
                ValidationFinding.FindingCategory.SECURITY,
                "NO_SECURITY_SCHEMES_DEFINED",
                null,
                null,
                "No security schemes defined in the API specification.",
                "Define appropriate security schemes (OAuth2, Bearer, API Key) in components/securitySchemes.",
                null
            ));
        } else {
            findings.addAll(validateSecuritySchemes());
        }

        // Check for HTTPS usage
        if (openAPI.getServers() != null) {
            boolean hasHttpServer = openAPI.getServers().stream()
                .anyMatch(server -> server.getUrl() != null &&
                    server.getUrl().toLowerCase().startsWith("http://"));

            if (hasHttpServer) {
                findings.add(new ValidationFinding(
                    Severity.HIGH,
                    ValidationFinding.FindingCategory.SECURITY,
                    "HTTP_SERVER_DEFINED",
                    null,
                    null,
                    "API server uses HTTP instead of HTTPS.",
                    "Use HTTPS for all API servers to ensure encrypted communication.",
                    null
                ));
            }
        }

        return findings;
    }

    private List<ValidationFinding> validateSecuritySchemes() {
        List<ValidationFinding> findings = new ArrayList<>();

        if (openAPI.getComponents() == null || openAPI.getComponents().getSecuritySchemes() == null) {
            return findings;
        }

        for (Map.Entry<String, SecurityScheme> entry : openAPI.getComponents().getSecuritySchemes().entrySet()) {
            String schemeName = entry.getKey();
            SecurityScheme scheme = entry.getValue();

            // Check for basic auth usage
            if (scheme.getType() == SecurityScheme.Type.HTTP &&
                "basic".equalsIgnoreCase(scheme.getScheme())) {

                findings.add(new ValidationFinding(
                    Severity.MEDIUM,
                    ValidationFinding.FindingCategory.SECURITY,
                    "BASIC_AUTH_USAGE",
                    null,
                    null,
                    String.format("Security scheme '%s' uses Basic Authentication.", schemeName),
                    "Consider using more secure authentication methods like OAuth2 or API tokens.",
                    Map.of("schemeName", schemeName)
                ));
            }

            // Check for API key in query
            if (scheme.getType() == SecurityScheme.Type.APIKEY &&
                SecurityScheme.In.QUERY.equals(scheme.getIn())) {

                findings.add(new ValidationFinding(
                    Severity.HIGH,
                    ValidationFinding.FindingCategory.SECURITY,
                    "API_KEY_IN_QUERY",
                    null,
                    null,
                    String.format("Security scheme '%s' passes API key in query parameter.", schemeName),
                    "Use header-based API keys instead of query parameters to prevent key exposure in logs.",
                    Map.of("schemeName", schemeName, "parameterName", scheme.getName())
                ));
            }
        }

        return findings;
    }

    private List<ValidationFinding> validateOperationSecurity(OperationSpec op) {
        List<ValidationFinding> findings = new ArrayList<>();

        // Check for unauthenticated sensitive operations
        if (!op.requiresAuthentication()) {
            boolean isSensitive = op.getMethod().matches("POST|PUT|PATCH|DELETE") ||
                                op.getPath().toLowerCase().contains("admin") ||
                                op.getPath().toLowerCase().contains("user");

            if (isSensitive) {
                findings.add(new ValidationFinding(
                    Severity.HIGH,
                    ValidationFinding.FindingCategory.SECURITY,
                    "UNAUTHENTICATED_SENSITIVE_OPERATION",
                    op.getPath(),
                    op.getMethod(),
                    "Sensitive operation does not require authentication.",
                    "Add security requirements to protect this endpoint.",
                    null
                ));
            }
        }

        // Check for missing authorization on resource access
        // Use case-insensitive regex to match parameter names containing "id"
        if (op.getPath().toLowerCase().matches(".*\\{.*id.*\\}.*") && !op.requiresAuthentication()) {
            findings.add(new ValidationFinding(
                Severity.MEDIUM,
                ValidationFinding.FindingCategory.SECURITY,
                "POTENTIAL_IDOR_VULNERABILITY",
                op.getPath(),
                op.getMethod(),
                "Operation accesses resources by ID without authentication, potential IDOR vulnerability.",
                "Implement authentication and authorization checks to prevent unauthorized resource access.",
                Map.of("vulnerability", "IDOR")
            ));
        }

        return findings;
    }
}
