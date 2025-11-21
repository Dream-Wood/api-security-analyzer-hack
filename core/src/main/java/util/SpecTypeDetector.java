package util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import model.SpecificationType;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;

/**
 * Utility class for detecting the type of API specification file.
 */
public final class SpecTypeDetector {

    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();
    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());

    private SpecTypeDetector() {
        // Utility class
    }

    /**
     * Detects the specification type from a file path or URL.
     *
     * @param specLocation path or URL to the specification file
     * @return the detected specification type
     * @throws IOException if file cannot be read
     * @throws IllegalArgumentException if specification type cannot be determined
     */
    public static SpecificationType detectType(String specLocation) throws IOException {
        String content;

        // Check if it's a URL
        if (specLocation.startsWith("http://") || specLocation.startsWith("https://")) {
            content = fetchFromUrl(specLocation);
        } else {
            // It's a file path
            Path path = Paths.get(specLocation);

            if (!Files.exists(path)) {
                throw new IOException("File does not exist: " + specLocation);
            }

            if (!Files.isRegularFile(path)) {
                throw new IOException("Path is not a file: " + specLocation);
            }

            // Read file content
            content = Files.readString(path);
        }

        // Try to parse as JSON or YAML
        JsonNode root = parseContent(content, specLocation);

        // Check for specification type fields
        if (root.has("openapi")) {
            return SpecificationType.OPENAPI;
        } else if (root.has("swagger")) {
            return SpecificationType.OPENAPI;
        } else if (root.has("asyncapi")) {
            return SpecificationType.ASYNCAPI;
        }

        throw new IllegalArgumentException(
            "Cannot determine specification type. File must contain 'openapi', 'swagger', or 'asyncapi' field."
        );
    }

    /**
     * Detects the specification type and returns a result with additional information.
     *
     * @param specLocation path to the specification file or URL
     * @return detection result with type and version information
     */
    public static DetectionResult detectTypeWithVersion(String specLocation) {
        try {
            String content;

            // Check if it's a URL
            if (specLocation.startsWith("http://") || specLocation.startsWith("https://")) {
                content = fetchFromUrl(specLocation);
            } else {
                // It's a file path
                Path path = Paths.get(specLocation);

                if (!Files.exists(path)) {
                    return DetectionResult.error("File does not exist: " + specLocation);
                }

                if (!Files.isRegularFile(path)) {
                    return DetectionResult.error("Path is not a file: " + specLocation);
                }

                content = Files.readString(path);
            }

            JsonNode root = parseContent(content, specLocation);

            if (root.has("openapi")) {
                String version = root.get("openapi").asText();
                return DetectionResult.success(SpecificationType.OPENAPI, version);
            } else if (root.has("swagger")) {
                String version = root.get("swagger").asText();
                return DetectionResult.success(SpecificationType.OPENAPI, version);
            } else if (root.has("asyncapi")) {
                String version = root.get("asyncapi").asText();
                return DetectionResult.success(SpecificationType.ASYNCAPI, version);
            }

            return DetectionResult.error(
                "Cannot determine specification type. File must contain 'openapi', 'swagger', or 'asyncapi' field."
            );

        } catch (IOException e) {
            return DetectionResult.error("Failed to read spec: " + e.getMessage());
        } catch (Exception e) {
            return DetectionResult.error("Error: " + e.getMessage());
        }
    }

    /**
     * Fetches content from a URL.
     *
     * @param url the URL to fetch from
     * @return the content as a string
     * @throws IOException if the request fails
     */
    private static String fetchFromUrl(String url) throws IOException {
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(30))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(30))
                    .header("Accept", "application/yaml, application/json, text/yaml, text/plain, */*")
                    .header("User-Agent", "API-Security-Analyzer/1.0")
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new IOException("HTTP " + response.statusCode() + " when fetching URL: " + url);
            }

            return response.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Request interrupted", e);
        }
    }

    private static JsonNode parseContent(String content, String filePath) throws IOException {
        // Try JSON first
        if (content.trim().startsWith("{")) {
            try {
                return JSON_MAPPER.readTree(content);
            } catch (IOException e) {
                // Fall through to YAML
            }
        }

        // Try YAML
        try {
            return YAML_MAPPER.readTree(content);
        } catch (IOException e) {
            throw new IOException("Failed to parse file as JSON or YAML: " + filePath, e);
        }
    }

    /**
     * Result of specification type detection.
     */
    public static final class DetectionResult {
        private final SpecificationType type;
        private final String version;
        private final boolean success;
        private final String errorMessage;

        private DetectionResult(SpecificationType type, String version, boolean success, String errorMessage) {
            this.type = type;
            this.version = version;
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public static DetectionResult success(SpecificationType type, String version) {
            return new DetectionResult(type, version, true, null);
        }

        public static DetectionResult error(String errorMessage) {
            return new DetectionResult(null, null, false, errorMessage);
        }

        public SpecificationType getType() {
            return type;
        }

        public String getVersion() {
            return version;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public boolean isAsyncApi() {
            return success && type == SpecificationType.ASYNCAPI;
        }

        public boolean isOpenApi() {
            return success && type == SpecificationType.OPENAPI;
        }
    }
}
