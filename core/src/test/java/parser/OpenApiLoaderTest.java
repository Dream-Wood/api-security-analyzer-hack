package parser;

import io.swagger.v3.oas.models.OpenAPI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class OpenApiLoaderTest {

    @TempDir
    Path tempDir;

    @Test
    void loadValidSpec_shouldSucceed() throws IOException {
        String yaml = """
                openapi: 3.0.1
                info:
                  title: Test API
                  version: 1.0.0
                paths:
                  /ping:
                    get:
                      operationId: ping
                      responses:
                        '200':
                          description: OK
                          content:
                            application/json:
                              schema:
                                type: object
                                properties:
                                  pong:
                                    type: string
                """;

        Path specFile = tempDir.resolve("openapi.yaml");
        Files.writeString(specFile, yaml);

        OpenApiLoader loader = new OpenApiLoader();
        OpenApiLoader.LoadResult result = loader.load(specFile.toString());

        assertNotNull(result, "Result should not be null");
        assertTrue(result.isSuccessful(), "Load should be successful");
        assertNotNull(result.getOpenAPI(), "OpenAPI should not be null");

        OpenAPI api = result.getOpenAPI();
        assertNotNull(api.getInfo(), "Info should not be null");
        assertEquals("Test API", api.getInfo().getTitle());
        assertTrue(api.getPaths().containsKey("/ping"));
    }

    @Test
    void loadInvalidSpec_shouldFail() throws IOException {
        String invalidYaml = """
                openapi: 3.0.1
                info:
                  title: Invalid
                  version: 1.0.0
                paths:
                  /test
                    get:  # Missing colon before 'get'
                      responses
                        200:
                          description: OK
                """;

        Path specFile = tempDir.resolve("invalid.yaml");
        Files.writeString(specFile, invalidYaml);

        OpenApiLoader loader = new OpenApiLoader();
        OpenApiLoader.LoadResult result = loader.load(specFile.toString());

        assertNotNull(result);
        assertFalse(result.isSuccessful(), "Load should fail for invalid YAML");
        assertNull(result.getOpenAPI(), "OpenAPI should be null for invalid spec");
        assertTrue(result.hasMessages(), "Should have error messages");
    }

    @Test
    void loadNonExistentFile_shouldFail() {
        OpenApiLoader loader = new OpenApiLoader();
        OpenApiLoader.LoadResult result = loader.load("/non/existent/file.yaml");

        assertNotNull(result);
        assertFalse(result.isSuccessful());
        assertNull(result.getOpenAPI());
        assertTrue(result.hasMessages());
    }

    @Test
    void loadWithMissingPaths_shouldSucceedWithWarning() throws IOException {
        String yaml = """
                openapi: 3.0.1
                info:
                  title: Empty API
                  version: 1.0.0
                """;

        Path specFile = tempDir.resolve("empty.yaml");
        Files.writeString(specFile, yaml);

        OpenApiLoader loader = new OpenApiLoader();
        OpenApiLoader.LoadResult result = loader.load(specFile.toString());

        assertTrue(result.isSuccessful(), "Should parse successfully");
        assertNotNull(result.getOpenAPI());
        assertTrue(result.hasMessages(), "Should have warning about missing paths");
    }

    @Test
    void isUrl_shouldDetectUrls() {
        assertTrue(OpenApiLoader.isUrl("http://example.com/api.yaml"));
        assertTrue(OpenApiLoader.isUrl("https://example.com/api.yaml"));
        assertFalse(OpenApiLoader.isUrl("/path/to/file.yaml"));
        assertFalse(OpenApiLoader.isUrl("file.yaml"));
        assertFalse(OpenApiLoader.isUrl(null));
    }
}
