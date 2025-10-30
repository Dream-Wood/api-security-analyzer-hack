package validator;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.parser.OpenAPIV3Parser;
import model.ValidationFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SecurityValidatorTest {

    @Test
    void validate_noSecuritySchemes_shouldDetect() {
        String yaml = """
                openapi: 3.0.1
                info:
                  title: Unsecured API
                  version: 1.0.0
                paths:
                  /test:
                    get:
                      responses:
                        '200':
                          description: OK
                """;

        OpenAPI openAPI = new OpenAPIV3Parser().readContents(yaml).getOpenAPI();
        SecurityValidator validator = new SecurityValidator(openAPI);
        List<ValidationFinding> findings = validator.validate();

        boolean hasNoSecuritySchemes = findings.stream()
            .anyMatch(f -> "NO_SECURITY_SCHEMES_DEFINED".equals(f.getType()));

        assertTrue(hasNoSecuritySchemes, "Should detect missing security schemes");
    }

    @Test
    void validate_httpServer_shouldDetect() {
        String yaml = """
                openapi: 3.0.1
                info:
                  title: Test API
                  version: 1.0.0
                servers:
                  - url: http://api.example.com
                paths:
                  /test:
                    get:
                      responses:
                        '200':
                          description: OK
                """;

        OpenAPI openAPI = new OpenAPIV3Parser().readContents(yaml).getOpenAPI();
        SecurityValidator validator = new SecurityValidator(openAPI);
        List<ValidationFinding> findings = validator.validate();

        boolean hasHttpServer = findings.stream()
            .anyMatch(f -> "HTTP_SERVER_DEFINED".equals(f.getType()));

        assertTrue(hasHttpServer, "Should detect HTTP server");
    }

    @Test
    void validate_basicAuth_shouldWarn() {
        String yaml = """
                openapi: 3.0.1
                info:
                  title: Test API
                  version: 1.0.0
                components:
                  securitySchemes:
                    basicAuth:
                      type: http
                      scheme: basic
                paths:
                  /test:
                    get:
                      security:
                        - basicAuth: []
                      responses:
                        '200':
                          description: OK
                """;

        OpenAPI openAPI = new OpenAPIV3Parser().readContents(yaml).getOpenAPI();
        SecurityValidator validator = new SecurityValidator(openAPI);
        List<ValidationFinding> findings = validator.validate();

        boolean hasBasicAuthWarning = findings.stream()
            .anyMatch(f -> "BASIC_AUTH_USAGE".equals(f.getType()));

        assertTrue(hasBasicAuthWarning, "Should warn about basic auth usage");
    }

    @Test
    void validate_apiKeyInQuery_shouldDetect() {
        String yaml = """
                openapi: 3.0.1
                info:
                  title: Test API
                  version: 1.0.0
                components:
                  securitySchemes:
                    apiKey:
                      type: apiKey
                      in: query
                      name: api_key
                paths:
                  /test:
                    get:
                      responses:
                        '200':
                          description: OK
                """;

        OpenAPI openAPI = new OpenAPIV3Parser().readContents(yaml).getOpenAPI();
        SecurityValidator validator = new SecurityValidator(openAPI);
        List<ValidationFinding> findings = validator.validate();

        boolean hasApiKeyInQuery = findings.stream()
            .anyMatch(f -> "API_KEY_IN_QUERY".equals(f.getType()));

        assertTrue(hasApiKeyInQuery, "Should detect API key in query parameter");
    }

    @Test
    void validate_unauthenticatedSensitiveEndpoint_shouldDetect() {
        String yaml = """
                openapi: 3.0.1
                info:
                  title: Test API
                  version: 1.0.0
                paths:
                  /admin/users:
                    delete:
                      responses:
                        '204':
                          description: Deleted
                """;

        OpenAPI openAPI = new OpenAPIV3Parser().readContents(yaml).getOpenAPI();
        SecurityValidator validator = new SecurityValidator(openAPI);
        List<ValidationFinding> findings = validator.validate();

        boolean hasSensitiveEndpoint = findings.stream()
            .anyMatch(f -> "UNAUTHENTICATED_SENSITIVE_OPERATION".equals(f.getType()));

        assertTrue(hasSensitiveEndpoint, "Should detect unauthenticated sensitive endpoint");
    }

    @Test
    void validate_potentialIdor_shouldDetect() {
        String yaml = """
                openapi: 3.0.1
                info:
                  title: Test API
                  version: 1.0.0
                paths:
                  /users/{userId}:
                    get:
                      parameters:
                        - name: userId
                          in: path
                          required: true
                          schema:
                            type: integer
                      responses:
                        '200':
                          description: OK
                """;

        OpenAPI openAPI = new OpenAPIV3Parser().readContents(yaml).getOpenAPI();
        SecurityValidator validator = new SecurityValidator(openAPI);
        List<ValidationFinding> findings = validator.validate();

        boolean hasIdor = findings.stream()
            .anyMatch(f -> "POTENTIAL_IDOR_VULNERABILITY".equals(f.getType()));

        assertTrue(hasIdor, "Should detect potential IDOR vulnerability");
    }
}
