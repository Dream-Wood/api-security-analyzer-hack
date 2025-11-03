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
        // Test basic context creation with GostTLS protocol
        GostTLSContext context = GostTLSContext.builder()
            .protocol(GostTLSContext.GostProtocol.GOST_TLS)
            .build();

        assertNotNull(context);
        assertEquals(GostTLSContext.GostProtocol.GOST_TLS, context.getProtocol());
        assertFalse(context.isTrustAllCertificates());
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testCreateGostTLSv13Context() {
        // Test context creation with GostTLSv1.3 protocol
        GostTLSContext context = GostTLSContext.builder()
            .protocol(GostTLSContext.GostProtocol.GOST_TLS_V1_3)
            .build();

        assertNotNull(context);
        assertEquals(GostTLSContext.GostProtocol.GOST_TLS_V1_3, context.getProtocol());
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testTrustAllCertificates() {
        // Test context with certificate verification disabled
        GostTLSContext context = GostTLSContext.builder()
            .protocol(GostTLSContext.GostProtocol.GOST_TLS)
            .trustAllCertificates(true)
            .build();

        assertNotNull(context);
        assertTrue(context.isTrustAllCertificates());
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testGetSSLContext() {
        // Test that we can retrieve a valid SSLContext
        GostTLSContext context = GostTLSContext.builder()
            .protocol(GostTLSContext.GostProtocol.GOST_TLS)
            .build();

        SSLContext sslContext = context.getSslContext();
        assertNotNull(sslContext);
        assertEquals("GostTLS", sslContext.getProtocol());
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testGetSocketFactory() {
        // Test that we can retrieve a valid SSLSocketFactory
        GostTLSContext context = GostTLSContext.builder()
            .protocol(GostTLSContext.GostProtocol.GOST_TLS)
            .build();

        SSLSocketFactory socketFactory = context.getSocketFactory();
        assertNotNull(socketFactory);
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testAutoDiscoverKeyContainers() {
        // Test HDImageStore auto-discovery
        assertDoesNotThrow(() -> {
            GostTLSContext context = GostTLSContext.builder()
                .protocol(GostTLSContext.GostProtocol.GOST_TLS)
                .autoDiscoverKeyContainers()
                .build();

            assertNotNull(context);
            assertNotNull(context.getKeyStore());
        });
    }

    @Test
    void testBuilderWithoutCryptoPro() {
        // This test should fail if CryptoPro is not available
        if (!CryptoProProvider.isAvailable()) {
            assertThrows(RuntimeException.class, () -> {
                GostTLSContext.builder()
                    .protocol(GostTLSContext.GostProtocol.GOST_TLS)
                    .build();
            });
        }
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testMultipleContexts() {
        // Test creating multiple contexts
        GostTLSContext context1 = GostTLSContext.builder()
            .protocol(GostTLSContext.GostProtocol.GOST_TLS)
            .build();

        GostTLSContext context2 = GostTLSContext.builder()
            .protocol(GostTLSContext.GostProtocol.GOST_TLS_V1_3)
            .build();

        assertNotNull(context1);
        assertNotNull(context2);
        assertNotEquals(context1.getProtocol(), context2.getProtocol());
    }
}
