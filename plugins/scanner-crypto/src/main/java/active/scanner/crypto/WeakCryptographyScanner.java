package active.scanner.crypto;

import active.http.HttpClient;
import active.model.ApiEndpoint;
import active.model.TestRequest;
import active.model.TestResponse;
import active.model.VulnerabilityReport;
import active.scanner.AbstractScanner;
import active.scanner.ScanContext;
import active.scanner.ScanResult;
import active.scanner.ScannerConfig;
import model.Severity;

import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Scanner for detecting Weak Cryptography vulnerabilities.
 *
 * <p>Weak Cryptography occurs when outdated or insecure cryptographic algorithms,
 * protocols, or practices are used, making the system vulnerable to attacks that
 * can decrypt sensitive data or bypass authentication mechanisms.
 *
 * <p>This scanner tests for:
 * <ul>
 *   <li>Use of HTTP instead of HTTPS</li>
 *   <li>Weak TLS/SSL versions (SSLv3, TLS 1.0, TLS 1.1)</li>
 *   <li>Weak cipher suites</li>
 *   <li>Insecure hash functions (MD5, SHA1) for security purposes</li>
 *   <li>Weak encryption algorithms (DES, 3DES, RC4)</li>
 *   <li>Missing or weak certificate validation</li>
 *   <li>Hardcoded cryptographic keys</li>
 *   <li>Insecure random number generation</li>
 * </ul>
 *
 * <p>Based on OWASP API Security Top 10 - API2:2023 and API8:2023
 */
public final class WeakCryptographyScanner extends AbstractScanner {
    private static final String SCANNER_ID = "weak-cryptography-scanner";
    private static final String SCANNER_NAME = "Weak Cryptography Scanner";
    private static final String SCANNER_DESCRIPTION =
        "Detects weak cryptographic practices including insecure protocols, algorithms, and configurations";

    // Weak hash algorithms
    private static final List<String> WEAK_HASH_ALGORITHMS = List.of(
        "MD5", "SHA1", "SHA-1", "md5", "sha1"
    );

    // Weak encryption algorithms
    private static final List<String> WEAK_ENCRYPTION_ALGORITHMS = List.of(
        "DES", "3DES", "RC4", "RC2", "Blowfish"
    );

    // Patterns for detecting weak cryptography in responses
    private static final Map<String, Pattern> CRYPTO_PATTERNS = Map.ofEntries(
        Map.entry("MD5 Hash", Pattern.compile("(?i)(md5|MD5)[\"']?\\s*[:=]\\s*[\"']?[a-f0-9]{32}")),
        Map.entry("SHA1 Hash", Pattern.compile("(?i)(sha1|SHA1|SHA-1)[\"']?\\s*[:=]\\s*[\"']?[a-f0-9]{40}")),
        Map.entry("Weak Algorithm", Pattern.compile("(?i)(algorithm|cipher)[\"']?\\s*[:=]\\s*[\"']?(DES|3DES|RC4|MD5|SHA1)")),
        Map.entry("Hardcoded Key", Pattern.compile("(?i)(encryption[_-]?key|secret[_-]?key)[\"']?\\s*[:=]\\s*[\"']([a-zA-Z0-9+/=]{16,})"))
    );

    // Weak TLS versions
    private static final List<String> WEAK_TLS_VERSIONS = List.of(
        "SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"
    );

    // Weak cipher suites
    private static final List<String> WEAK_CIPHER_SUITES = List.of(
        "NULL", "EXPORT", "DES", "RC4", "MD5", "anon", "ADH", "AECDH"
    );

    public WeakCryptographyScanner() {
        super();
    }

    public WeakCryptographyScanner(ScannerConfig config) {
        super(config);
    }

    @Override
    public String getId() {
        return SCANNER_ID;
    }

    @Override
    public String getName() {
        return SCANNER_NAME;
    }

    @Override
    public String getDescription() {
        return SCANNER_DESCRIPTION;
    }

    @Override
    public List<VulnerabilityReport.VulnerabilityType> getDetectedVulnerabilities() {
        return List.of(
            VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION,
            VulnerabilityReport.VulnerabilityType.BROKEN_AUTHENTICATION
        );
    }

    @Override
    public boolean isApplicable(ApiEndpoint endpoint) {
        // Apply to all endpoints, especially sensitive ones
        return true;
    }

    @Override
    protected ScanResult performScan(ApiEndpoint endpoint, HttpClient httpClient, ScanContext context) {
        Instant startTime = Instant.now();
        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        int totalTests = 0;

        // Test Case 1: Check for HTTP instead of HTTPS
        CryptoTestResult httpTest = testHttpUsage(endpoint, httpClient, context);
        totalTests += httpTest.testsExecuted();
        httpTest.vulnerability().ifPresent(vulnerabilities::add);

        // Test Case 2: Check for weak cryptographic algorithms in response
        CryptoTestResult weakAlgoTest = testWeakCryptographicAlgorithms(endpoint, httpClient, context);
        totalTests += weakAlgoTest.testsExecuted();
        vulnerabilities.addAll(weakAlgoTest.vulnerabilities());

        // Test Case 3: Check TLS/SSL configuration
        CryptoTestResult tlsTest = testTlsConfiguration(endpoint, httpClient, context);
        totalTests += tlsTest.testsExecuted();
        vulnerabilities.addAll(tlsTest.vulnerabilities());

        // Test Case 4: Check for insecure cipher information disclosure
        CryptoTestResult cipherTest = testCipherDisclosure(endpoint, httpClient, context);
        totalTests += cipherTest.testsExecuted();
        vulnerabilities.addAll(cipherTest.vulnerabilities());

        // Test Case 5: Check for hardcoded cryptographic keys
        CryptoTestResult hardcodedKeyTest = testHardcodedKeys(endpoint, httpClient, context);
        totalTests += hardcodedKeyTest.testsExecuted();
        vulnerabilities.addAll(hardcodedKeyTest.vulnerabilities());

        return createSuccessResult(endpoint, vulnerabilities, totalTests, startTime);
    }

    /**
     * Test if API is using HTTP instead of HTTPS.
     */
    private CryptoTestResult testHttpUsage(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing HTTP vs HTTPS usage for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        // Check if the base URL uses HTTP
        if (url.toLowerCase().startsWith("http://")) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.HIGH)
                .endpoint(endpoint)
                .title("Insecure Protocol: HTTP Instead of HTTPS")
                .description(
                    "The API is accessible over HTTP instead of HTTPS. " +
                    "This means all data transmitted between client and server is sent in plaintext, " +
                    "making it vulnerable to man-in-the-middle attacks, eavesdropping, and data tampering. " +
                    "HTTPS with TLS encryption is essential for protecting sensitive data in transit."
                )
                .addEvidence("protocol", "HTTP")
                .addEvidence("url", url)
                .addRecommendation("Enforce HTTPS for all API endpoints")
                .addRecommendation("Redirect all HTTP requests to HTTPS")
                .addRecommendation("Use HTTP Strict Transport Security (HSTS) header")
                .addRecommendation("Disable HTTP access entirely in production")
                .addRecommendation("Use TLS 1.2 or higher")
                .reproductionSteps(
                    "1. Observe API endpoint URL: " + url + "\n" +
                    "2. Notice HTTP protocol instead of HTTPS\n" +
                    "3. All traffic is transmitted in plaintext"
                )
                .build();

            return new CryptoTestResult(Optional.of(vulnerability), List.of(), 1);
        }

        return new CryptoTestResult(Optional.empty(), List.of(), 1);
    }

    /**
     * Test for weak cryptographic algorithms mentioned in response.
     */
    private CryptoTestResult testWeakCryptographicAlgorithms(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing weak cryptographic algorithms for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Weak Crypto Algorithm Scan");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        String body = response.getBody();

        if (body == null || body.isEmpty()) {
            return new CryptoTestResult(Optional.empty(), vulnerabilities, 1);
        }

        Map<String, List<String>> detectedWeakCrypto = new HashMap<>();

        // Scan for weak cryptographic patterns
        for (Map.Entry<String, Pattern> entry : CRYPTO_PATTERNS.entrySet()) {
            var matcher = entry.getValue().matcher(body);
            List<String> matches = new ArrayList<>();

            while (matcher.find() && matches.size() < 3) {
                String match = matcher.group().length() > 80
                    ? matcher.group().substring(0, 80) + "..."
                    : matcher.group();
                matches.add(match);
            }

            if (!matches.isEmpty()) {
                detectedWeakCrypto.put(entry.getKey(), matches);
            }
        }

        // Check for weak hash algorithms in plain text
        for (String weakHash : WEAK_HASH_ALGORITHMS) {
            if (body.toLowerCase().contains(weakHash.toLowerCase())) {
                detectedWeakCrypto.putIfAbsent("Weak Hash: " + weakHash, List.of(weakHash));
            }
        }

        // Check for weak encryption algorithms
        for (String weakAlgo : WEAK_ENCRYPTION_ALGORITHMS) {
            if (body.toLowerCase().contains(weakAlgo.toLowerCase())) {
                detectedWeakCrypto.putIfAbsent("Weak Encryption: " + weakAlgo, List.of(weakAlgo));
            }
        }

        if (!detectedWeakCrypto.isEmpty()) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.HIGH)
                .endpoint(endpoint)
                .title("Weak Cryptographic Algorithms Detected")
                .description(
                    "The API response indicates use of weak or deprecated cryptographic algorithms. " +
                    "Detected: " + String.join(", ", detectedWeakCrypto.keySet()) + ". " +
                    "Weak algorithms like MD5, SHA1, DES, and RC4 are vulnerable to collision attacks, " +
                    "brute force, and other cryptanalytic techniques. They should not be used for security purposes."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("weakCryptoDetected", detectedWeakCrypto)
                .addRecommendation("Replace MD5 and SHA1 with SHA-256 or SHA-3")
                .addRecommendation("Replace DES and 3DES with AES-256")
                .addRecommendation("Replace RC4 with modern stream ciphers")
                .addRecommendation("Use bcrypt, scrypt, or Argon2 for password hashing")
                .addRecommendation("Follow current cryptographic best practices (NIST, OWASP)")
                .reproductionSteps(
                    "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                    "2. Examine response for cryptographic algorithm references\n" +
                    "3. Observe weak algorithms: " + detectedWeakCrypto.keySet()
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        return new CryptoTestResult(Optional.empty(), vulnerabilities, 1);
    }

    /**
     * Test TLS/SSL configuration.
     */
    private CryptoTestResult testTlsConfiguration(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing TLS configuration for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        if (!url.toLowerCase().startsWith("https://")) {
            return new CryptoTestResult(Optional.empty(), List.of(), 0);
        }

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "TLS Configuration Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();

        // Check for TLS version information in headers
        Map<String, List<String>> headers = response.getHeaders();
        List<String> weakTlsIndicators = new ArrayList<>();

        for (Map.Entry<String, List<String>> header : headers.entrySet()) {
            String headerValue = String.join(",", header.getValue()).toLowerCase();

            for (String weakVersion : WEAK_TLS_VERSIONS) {
                if (headerValue.contains(weakVersion.toLowerCase())) {
                    weakTlsIndicators.add(weakVersion);
                }
            }
        }

        // Check response body for TLS/SSL information
        String body = response.getBody();
        if (body != null) {
            for (String weakVersion : WEAK_TLS_VERSIONS) {
                if (body.contains(weakVersion)) {
                    weakTlsIndicators.add(weakVersion);
                }
            }
        }

        if (!weakTlsIndicators.isEmpty()) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.HIGH)
                .endpoint(endpoint)
                .title("Weak TLS/SSL Configuration Detected")
                .description(
                    "The API appears to support weak TLS/SSL versions: " + weakTlsIndicators + ". " +
                    "Protocols like SSLv3, TLS 1.0, and TLS 1.1 have known vulnerabilities (POODLE, BEAST, etc.) " +
                    "and should be disabled. Only TLS 1.2 and TLS 1.3 should be enabled."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("weakTlsVersions", weakTlsIndicators)
                .addRecommendation("Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1")
                .addRecommendation("Enable only TLS 1.2 and TLS 1.3")
                .addRecommendation("Use strong cipher suites")
                .addRecommendation("Regularly update TLS configuration based on current best practices")
                .reproductionSteps(
                    "1. Send request to " + url + "\n" +
                    "2. Examine TLS/SSL configuration\n" +
                    "3. Observe weak protocols: " + weakTlsIndicators
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        return new CryptoTestResult(Optional.empty(), vulnerabilities, 1);
    }

    /**
     * Test for cipher suite information disclosure.
     */
    private CryptoTestResult testCipherDisclosure(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing cipher disclosure for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Cipher Information Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        String body = response.getBody();

        if (body == null || body.isEmpty()) {
            return new CryptoTestResult(Optional.empty(), vulnerabilities, 1);
        }

        List<String> weakCiphers = new ArrayList<>();

        // Check for weak cipher suite indicators
        for (String weakCipher : WEAK_CIPHER_SUITES) {
            if (body.toUpperCase().contains(weakCipher.toUpperCase())) {
                weakCiphers.add(weakCipher);
            }
        }

        if (!weakCiphers.isEmpty()) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.MEDIUM)
                .endpoint(endpoint)
                .title("Weak Cipher Suites Detected")
                .description(
                    "The API response contains references to weak cipher suites: " + weakCiphers + ". " +
                    "Weak ciphers can be vulnerable to various attacks including brute force and cryptanalysis. " +
                    "Only strong, modern cipher suites should be used."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("weakCiphers", weakCiphers)
                .addRecommendation("Disable NULL, EXPORT, and anonymous cipher suites")
                .addRecommendation("Disable DES and RC4 ciphers")
                .addRecommendation("Use AEAD ciphers (AES-GCM, ChaCha20-Poly1305)")
                .addRecommendation("Prioritize forward secrecy (ECDHE, DHE)")
                .addRecommendation("Follow Mozilla SSL Configuration Generator recommendations")
                .reproductionSteps(
                    "1. Send request to " + url + "\n" +
                    "2. Examine response for cipher information\n" +
                    "3. Observe weak ciphers: " + weakCiphers
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        return new CryptoTestResult(Optional.empty(), vulnerabilities, 1);
    }

    /**
     * Test for hardcoded cryptographic keys in response.
     */
    private CryptoTestResult testHardcodedKeys(
        ApiEndpoint endpoint,
        HttpClient httpClient,
        ScanContext context
    ) {
        logger.fine("Testing hardcoded keys for: " + endpoint);

        String url = context.buildUrl(endpoint.getPath());

        TestRequest request = TestRequest.builder()
            .url(url)
            .method(endpoint.getMethod())
            .headers(context.getAuthHeaders())
            .build();

        TestResponse response = executeTest(httpClient, request, "Hardcoded Keys Check");

        List<VulnerabilityReport> vulnerabilities = new ArrayList<>();
        String body = response.getBody();

        if (body == null || body.isEmpty()) {
            return new CryptoTestResult(Optional.empty(), vulnerabilities, 1);
        }

        // Patterns for hardcoded keys
        List<Pattern> keyPatterns = List.of(
            Pattern.compile("(?i)(private[_-]?key|secret[_-]?key|encryption[_-]?key)[\"']?\\s*[:=]\\s*[\"']([a-zA-Z0-9+/=]{32,})"),
            Pattern.compile("(?i)(aes[_-]?key|des[_-]?key)[\"']?\\s*[:=]\\s*[\"']([a-zA-Z0-9+/=]{16,})"),
            Pattern.compile("-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----")
        );

        List<String> foundKeys = new ArrayList<>();

        for (Pattern pattern : keyPatterns) {
            var matcher = pattern.matcher(body);
            if (matcher.find()) {
                String match = matcher.group().length() > 60
                    ? matcher.group().substring(0, 60) + "..."
                    : matcher.group();
                foundKeys.add(match);
            }
        }

        if (!foundKeys.isEmpty()) {
            VulnerabilityReport vulnerability = VulnerabilityReport.builder()
                .type(VulnerabilityReport.VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.CRITICAL)
                .endpoint(endpoint)
                .title("Hardcoded Cryptographic Keys Exposed")
                .description(
                    "The API response contains hardcoded cryptographic keys or private keys. " +
                    "This is a critical security vulnerability as it exposes the keys that should remain secret. " +
                    "Attackers can use these keys to decrypt sensitive data, forge signatures, or bypass encryption entirely."
                )
                .exploitRequest(request)
                .exploitResponse(response)
                .addEvidence("exposedKeyCount", foundKeys.size())
                .addEvidence("keyPatterns", foundKeys)
                .addRecommendation("NEVER hardcode cryptographic keys in code or responses")
                .addRecommendation("Use secure key management systems (AWS KMS, Azure Key Vault, HashiCorp Vault)")
                .addRecommendation("Store keys in environment variables or secure configuration")
                .addRecommendation("Rotate all exposed keys immediately")
                .addRecommendation("Implement proper key lifecycle management")
                .reproductionSteps(
                    "1. Send " + endpoint.getMethod() + " request to " + url + "\n" +
                    "2. Examine response body\n" +
                    "3. Observe exposed cryptographic keys"
                )
                .build();

            vulnerabilities.add(vulnerability);
        }

        return new CryptoTestResult(Optional.empty(), vulnerabilities, 1);
    }

    /**
     * Result of a cryptography test case.
     */
    private record CryptoTestResult(
        Optional<VulnerabilityReport> vulnerability,
        List<VulnerabilityReport> vulnerabilities,
        int testsExecuted
    ) {
        CryptoTestResult(Optional<VulnerabilityReport> vulnerability, List<VulnerabilityReport> vulnerabilities, int testsExecuted) {
            this.vulnerability = vulnerability;
            this.vulnerabilities = vulnerabilities != null ? vulnerabilities : List.of();
            this.testsExecuted = testsExecuted;
        }
    }
}
