package active.http.ssl;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for CryptoProProvider.
 *
 * <p>Note: Tests requiring CryptoPro JCSP libraries are disabled by default.
 * Enable with: -Dcryptopro.available=true
 */
class CryptoProProviderTest {

    @Test
    void testIsAvailable() {
        // This test checks if CryptoPro is available on the system
        // It should not throw exceptions regardless of availability
        boolean available = CryptoProProvider.isAvailable();

        // We can't assert the result since it depends on the environment
        // but we can verify the method executes without errors
        assertNotNull(Boolean.valueOf(available));
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testInitialize() {
        // Test provider initialization
        assertDoesNotThrow(() -> CryptoProProvider.initialize());

        // Verify that initialization sets the flag
        assertTrue(CryptoProProvider.isInitialized());
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testInitializeIdempotent() {
        // Test that multiple calls to initialize() are safe
        CryptoProProvider.initialize();
        CryptoProProvider.initialize();
        CryptoProProvider.initialize();

        assertTrue(CryptoProProvider.isInitialized());
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testIsProviderAvailable() {
        // Test checking individual provider availability
        assertTrue(CryptoProProvider.isProviderAvailable(CryptoProProvider.ProviderType.JCP));
        assertTrue(CryptoProProvider.isProviderAvailable(CryptoProProvider.ProviderType.SSL));
        assertTrue(CryptoProProvider.isProviderAvailable(CryptoProProvider.ProviderType.CRYPTO));

        // RevCheck is optional
        // boolean revCheckAvailable = CryptoProProvider.isProviderAvailable(
        //     CryptoProProvider.ProviderType.REVCHECK
        // );
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testRegisterProvider() {
        // Test registering individual provider
        assertDoesNotThrow(() ->
            CryptoProProvider.registerProvider(CryptoProProvider.ProviderType.JCP)
        );

        assertTrue(CryptoProProvider.isProviderRegistered(CryptoProProvider.ProviderType.JCP));
    }

    @Test
    @EnabledIfSystemProperty(named = "cryptopro.available", matches = "true")
    void testGetRegisteredProviders() {
        // Initialize providers
        CryptoProProvider.initialize();

        // Get list of registered providers
        List<String> providers = CryptoProProvider.getRegisteredProviders();

        assertNotNull(providers);
        assertFalse(providers.isEmpty());

        // Should contain at least JCP and SSL providers
        assertTrue(providers.size() >= 2);
    }

    @Test
    void testProviderRegistrationWithoutCryptoPro() {
        // Test that registration fails gracefully without CryptoPro
        if (!CryptoProProvider.isAvailable()) {
            assertThrows(
                CryptoProProvider.ProviderRegistrationException.class,
                () -> CryptoProProvider.registerProvider(CryptoProProvider.ProviderType.JCP)
            );
        }
    }

    @Test
    void testProviderTypeEnum() {
        // Test ProviderType enum properties
        assertEquals("ru.CryptoPro.JCP.JCP",
            CryptoProProvider.ProviderType.JCP.getClassName());
        assertEquals("ru.CryptoPro.ssl.Provider",
            CryptoProProvider.ProviderType.SSL.getClassName());
        assertEquals("ru.CryptoPro.Crypto.CryptoProvider",
            CryptoProProvider.ProviderType.CRYPTO.getClassName());
        assertEquals("ru.CryptoPro.reprov.RevCheck",
            CryptoProProvider.ProviderType.REVCHECK.getClassName());

        // Check required flags
        assertTrue(CryptoProProvider.ProviderType.JCP.isRequired());
        assertTrue(CryptoProProvider.ProviderType.SSL.isRequired());
        assertTrue(CryptoProProvider.ProviderType.CRYPTO.isRequired());
        assertFalse(CryptoProProvider.ProviderType.REVCHECK.isRequired());
    }
}
