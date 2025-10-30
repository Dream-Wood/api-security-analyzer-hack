package validator;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.parser.OpenAPIV3Parser;
import model.Severity;
import model.ValidationFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class StaticContractValidatorTest {

    @Test
    void validate_missingSuccessResponse_shouldDetect() {
        String yaml = """
                openapi: 3.0.1
                info:
                  title: Test API
                  version: 1.0.0
                paths:
                  /test:
                    post:
                      responses:
                        '400':
                          description: Bad Request
                        '500':
                          description: Server Error
                """;

        OpenAPI openAPI = new OpenAPIV3Parser().readContents(yaml).getOpenAPI();
        StaticContractValidator validator = new StaticContractValidator(openAPI);
        List<ValidationFinding> findings = validator.validate();

        boolean hasMissing2xx = findings.stream()
            .anyMatch(f -> "MISSING_SUCCESS_RESPONSE".equals(f.getType()));

        assertTrue(hasMissing2xx, "Should detect missing 2xx response");
    }

    @Test
    void validate_missingSchema_shouldDetect() {
        String yaml = """
                openapi: 3.0.1
                info:
                  title: Test API
                  version: 1.0.0
                paths:
                  /test:
                    get:
                      responses:
                        '200':
                          description: OK
                """;

        OpenAPI openAPI = new OpenAPIV3Parser().readContents(yaml).getOpenAPI();
        StaticContractValidator validator = new StaticContractValidator(openAPI);
        List<ValidationFinding> findings = validator.validate();

        boolean hasMissingSchema = findings.stream()
            .anyMatch(f -> "MISSING_RESPONSE_SCHEMA".equals(f.getType()));

        assertTrue(hasMissingSchema, "Should detect missing response schema");
    }

    @Test
    void validate_wellDefinedApi_shouldPassOrHaveMinorIssues() {
        String yaml = """
                openapi: 3.0.1
                info:
                  title: Well Defined API
                  version: 1.0.0
                  description: A complete API specification
                paths:
                  /users:
                    get:
                      operationId: getUsers
                      summary: Get all users
                      responses:
                        '200':
                          description: List of users
                          content:
                            application/json:
                              schema:
                                type: array
                                items:
                                  type: object
                                  properties:
                                    id:
                                      type: integer
                                    name:
                                      type: string
                        '400':
                          description: Bad request
                components:
                  securitySchemes:
                    bearerAuth:
                      type: http
                      scheme: bearer
                security:
                  - bearerAuth: []
                """;

        OpenAPI openAPI = new OpenAPIV3Parser().readContents(yaml).getOpenAPI();
        StaticContractValidator validator = new StaticContractValidator(openAPI);
        List<ValidationFinding> findings = validator.validate();

        // Should not have HIGH or CRITICAL findings
        boolean hasCriticalOrHigh = findings.stream()
            .anyMatch(f -> f.getSeverity().isCriticalOrHigh());

        assertFalse(hasCriticalOrHigh,
            "Well-defined API should not have critical/high severity issues");
    }

    @Test
    void validate_unauthenticatedMutation_shouldDetect() {
        String yaml = """
                openapi: 3.0.1
                info:
                  title: Test API
                  version: 1.0.0
                paths:
                  /users:
                    post:
                      operationId: createUser
                      requestBody:
                        content:
                          application/json:
                            schema:
                              type: object
                      responses:
                        '201':
                          description: Created
                          content:
                            application/json:
                              schema:
                                type: object
                """;

        OpenAPI openAPI = new OpenAPIV3Parser().readContents(yaml).getOpenAPI();
        StaticContractValidator validator = new StaticContractValidator(openAPI);
        List<ValidationFinding> findings = validator.validate();

        boolean hasUnauthenticated = findings.stream()
            .anyMatch(f -> "UNAUTHENTICATED_MUTATION".equals(f.getType()));

        assertTrue(hasUnauthenticated, "Should detect unauthenticated mutation");
    }

    @Test
    void validate_deprecatedOperation_shouldDetect() {
        String yaml = """
                openapi: 3.0.1
                info:
                  title: Test API
                  version: 1.0.0
                paths:
                  /old-endpoint:
                    get:
                      deprecated: true
                      responses:
                        '200':
                          description: OK
                          content:
                            application/json:
                              schema:
                                type: object
                """;

        OpenAPI openAPI = new OpenAPIV3Parser().readContents(yaml).getOpenAPI();
        StaticContractValidator validator = new StaticContractValidator(openAPI);
        List<ValidationFinding> findings = validator.validate();

        boolean hasDeprecated = findings.stream()
            .anyMatch(f -> "DEPRECATED_OPERATION".equals(f.getType()));

        assertTrue(hasDeprecated, "Should detect deprecated operation");
    }
}
