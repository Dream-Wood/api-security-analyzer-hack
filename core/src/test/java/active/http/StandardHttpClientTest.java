package active.http;

import active.model.TestRequest;
import active.model.TestResponse;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Simple integration tests for StandardHttpClient using httpbin.org or local testing.
 */
class StandardHttpClientTest {

    @Test
    void testHttpClientCreation() {
        HttpClientConfig config = HttpClientConfig.builder()
            .cryptoProtocol(HttpClient.CryptoProtocol.STANDARD_TLS)
            .connectTimeout(Duration.ofSeconds(5))
            .readTimeout(Duration.ofSeconds(5))
            .build();

        StandardHttpClient httpClient = new StandardHttpClient(config);

        assertNotNull(httpClient);
        assertEquals(HttpClient.CryptoProtocol.STANDARD_TLS, httpClient.getCryptoProtocol());
        assertTrue(httpClient.supports("http://example.com"));
        assertTrue(httpClient.supports("https://example.com"));
        assertFalse(httpClient.supports("ftp://example.com"));

        httpClient.close();
    }

    @Test
    void testRequestBuilder() {
        TestRequest request = TestRequest.builder()
            .url("http://example.com/api/test")
            .method("GET")
            .addHeader("X-Test", "value")
            .addQueryParam("q", "search")
            .build();

        assertNotNull(request);
        assertEquals("GET", request.getMethod());
        assertEquals("http://example.com/api/test?q=search", request.getFullUrl());
        assertEquals("value", request.getHeaders().get("X-Test"));
    }

    @Test
    void testPostRequestWithBody() {
        TestRequest request = TestRequest.builder()
            .url("http://example.com/api/users")
            .method("POST")
            .body("{\"name\":\"test\"}")
            .bodyContentType("application/json")
            .build();

        assertNotNull(request);
        assertEquals("POST", request.getMethod());
        assertEquals("{\"name\":\"test\"}", request.getBody());
        assertEquals("application/json", request.getBodyContentType());
    }

    @Test
    void testInvalidUrlHandling() {
        HttpClientConfig config = HttpClientConfig.builder()
            .cryptoProtocol(HttpClient.CryptoProtocol.STANDARD_TLS)
            .build();

        StandardHttpClient httpClient = new StandardHttpClient(config);

        TestRequest request = TestRequest.builder()
            .url("invalid-url")
            .method("GET")
            .build();

        TestResponse response = httpClient.execute(request);

        // Should handle error gracefully
        assertTrue(response.hasError());
        assertEquals(0, response.getStatusCode());

        httpClient.close();
    }
}
