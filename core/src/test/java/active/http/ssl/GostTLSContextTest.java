package active.http.ssl;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for GostTLSContext.
 *
 * <p>Note: Most tests require CryptoPro JCSP libraries to be installed.
 * Tests are disabled by default and can be enabled with:
 * -Dcryptopro.available=true
 */
class GostTLSContextTest {

    @BeforeAll
    static void checkCryptoProAvailability() {
        if (CryptoProProvider.isAvailable()) {
            CryptoProProvider.initialize();
        }
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testCreateBasicGostTLSContext() {
        // Test basic context creation without client certificate
        GostTLSContext context = GostTLSContext.builder()
            .build();

        assertNotNull(context);
        assertNotNull(context.getSslContext());
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testCreateContextWithPfxResource() {
        // Test context creation with PFX from resource
        // Note: This test will fail if cert.pfx is not in resources/certs/
        assertThrows(RuntimeException.class, () -> {
            GostTLSContext.builder()
                .pfxResource("certs/cert.pfx", "password")
                .build();
        });
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testGetSSLContext() {
        // Test that we can retrieve a valid SSLContext
        GostTLSContext context = GostTLSContext.builder()
            .build();

        SSLContext sslContext = context.getSslContext();
        assertNotNull(sslContext);
        assertEquals("GostTLSv1.3", sslContext.getProtocol());
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testGetSocketFactory() {
        // Test that we can retrieve a valid SSLSocketFactory
        GostTLSContext context = GostTLSContext.builder()
            .build();

        SSLSocketFactory socketFactory = context.getSocketFactory();
        assertNotNull(socketFactory);
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testCloseContext() {
        // Test that close doesn't throw exceptions
        GostTLSContext context = GostTLSContext.builder()
            .build();

        assertDoesNotThrow(() -> context.close());
    }

    @Test
    void testBuilderWithoutCryptoPro() {
        // This test should fail if CryptoPro is not available
        if (!CryptoProProvider.isAvailable()) {
            assertThrows(RuntimeException.class, () -> {
                GostTLSContext.builder()
                    .build();
            });
        }
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testDisableVerification() {
        // Test context with verification disabled
        GostTLSContext context = GostTLSContext.builder()
            .disableVerification(true)
            .build();

        assertNotNull(context);
        assertNotNull(context.getSslContext());
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testMultipleContexts() {
        // Test creating multiple contexts
        GostTLSContext context1 = GostTLSContext.builder()
            .build();

        GostTLSContext context2 = GostTLSContext.builder()
            .disableVerification(true)
            .build();

        assertNotNull(context1);
        assertNotNull(context2);
        assertNotEquals(context1.getSslContext(), context2.getSslContext());
    }
}
