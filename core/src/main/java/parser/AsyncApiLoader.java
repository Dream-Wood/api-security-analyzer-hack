package parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.File;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Loads AsyncAPI specifications from files or URLs.
 */
public final class AsyncApiLoader {

    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();
    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());

    /**
     * Result of loading an AsyncAPI specification.
     */
    public static final class LoadResult {
        private final JsonNode asyncApiNode;
        private final List<String> messages;
        private final boolean successful;

        private LoadResult(JsonNode asyncApiNode, List<String> messages, boolean successful) {
            this.asyncApiNode = asyncApiNode;
            this.messages = messages != null ? List.copyOf(messages) : List.of();
            this.successful = successful;
        }

        public static LoadResult success(JsonNode asyncApiNode, List<String> messages) {
            return new LoadResult(asyncApiNode, messages, true);
        }

        public static LoadResult failure(List<String> messages) {
            return new LoadResult(null, messages, false);
        }

        public JsonNode getAsyncApiNode() {
            return asyncApiNode;
        }

        public List<String> getMessages() {
            return messages;
        }

        public boolean isSuccessful() {
            return successful;
        }

        public boolean hasMessages() {
            return !messages.isEmpty();
        }
    }

    /**
     * Loads an AsyncAPI specification from a file path or URL.
     *
     * @param location file path or URL to the specification
     * @return load result containing AsyncAPI node and any messages
     */
    public LoadResult load(String location) {
        Objects.requireNonNull(location, "location must not be null");

        try {
            String content;

            // Check if it's a URL
            if (isUrl(location)) {
                content = fetchFromUrl(location);
            } else {
                // It's a file path
                Path path = Paths.get(location);

                if (!Files.exists(path)) {
                    return LoadResult.failure(List.of("File does not exist: " + location));
                }

                if (!Files.isRegularFile(path)) {
                    return LoadResult.failure(List.of("Path is not a file: " + location));
                }

                content = Files.readString(path);
            }

            List<String> messages = new ArrayList<>();

            // Parse as JSON or YAML
            JsonNode asyncApiNode = parseContent(content, location);

            if (asyncApiNode == null) {
                return LoadResult.failure(List.of("Failed to parse AsyncAPI specification. The file may be invalid."));
            }

            // Validate it's an AsyncAPI spec
            if (!asyncApiNode.has("asyncapi")) {
                return LoadResult.failure(List.of("File is not an AsyncAPI specification. Missing 'asyncapi' field."));
            }

            // Check for required fields
            if (!asyncApiNode.has("info")) {
                messages.add("Warning: AsyncAPI specification missing 'info' section");
            }

            if (!asyncApiNode.has("channels") || asyncApiNode.get("channels").size() == 0) {
                messages.add("Warning: AsyncAPI specification has no channels defined");
            }

            return LoadResult.success(asyncApiNode, messages);

        } catch (Exception e) {
            List<String> messages = new ArrayList<>();
            messages.add("Exception during parsing: " + e.getMessage());
            return LoadResult.failure(messages);
        }
    }

    /**
     * Fetches content from a URL.
     *
     * @param url the URL to fetch from
     * @return the content as a string
     * @throws Exception if the request fails
     */
    private String fetchFromUrl(String url) throws Exception {
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(30))
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(30))
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new Exception("HTTP " + response.statusCode() + " when fetching URL: " + url);
            }

            return response.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new Exception("Request interrupted", e);
        }
    }

    private JsonNode parseContent(String content, String filePath) {
        // Try JSON first
        if (content.trim().startsWith("{")) {
            try {
                return JSON_MAPPER.readTree(content);
            } catch (Exception e) {
                // Fall through to YAML
            }
        }

        // Try YAML
        try {
            return YAML_MAPPER.readTree(content);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Checks if a location appears to be a URL.
     */
    public static boolean isUrl(String location) {
        if (location == null) {
            return false;
        }
        String lower = location.toLowerCase();
        return lower.startsWith("http://") || lower.startsWith("https://");
    }
}
