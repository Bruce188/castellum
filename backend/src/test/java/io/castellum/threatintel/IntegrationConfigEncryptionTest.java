package io.castellum.threatintel;

import io.castellum.security.AesGcmCipher;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that the {@code integration_config.encrypted_credentials} column
 * persists ciphertext bytes (not plaintext) and that a round-trip through
 * the JPA repository + {@link AesGcmCipher} recovers the original secret.
 *
 * <p>Uses an in-test {@link AesGcmCipher} with a generated 32-byte key —
 * we do NOT depend on the env-var key here so the test is hermetic.
 */
@DataJpaTest
@Import(IntegrationConfigEncryptionTest.TestConfig.class)
class IntegrationConfigEncryptionTest {

    @Autowired private IntegrationConfigRepository repository;
    @Autowired private AesGcmCipher cipher;
    @Autowired private JdbcTemplate jdbcTemplate;

    @org.springframework.boot.test.context.TestConfiguration
    static class TestConfig {
        @org.springframework.context.annotation.Bean
        AesGcmCipher cipher() {
            byte[] key = new byte[32];
            new java.security.SecureRandom().nextBytes(key);
            AesGcmCipher c = new AesGcmCipher(Base64.getEncoder().encodeToString(key));
            c.verifyKey();
            return c;
        }
    }

    @Test
    void persistedColumn_containsCiphertextNotPlaintext() {
        String secret = "rotate-me-please-XYZ123!";
        byte[] encrypted = cipher.encrypt(secret);
        IntegrationConfig saved = repository.saveAndFlush(
            new IntegrationConfig("TAXII", "{\"url\":\"https://taxii.example\"}", encrypted));

        // Read raw bytes back via JDBC to avoid any JPA caching shenanigans.
        Map<String, Object> row = jdbcTemplate.queryForMap(
            "SELECT encrypted_credentials FROM integration_config WHERE id = ?", saved.getId());
        Object raw = row.get("encrypted_credentials");
        assertNotNull(raw, "encrypted_credentials must be persisted");
        byte[] bytes = (byte[]) raw;
        // Plaintext must not appear contiguously in the stored bytes.
        byte[] plain = secret.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i <= bytes.length - plain.length; i++) {
            boolean matched = true;
            for (int j = 0; j < plain.length; j++) {
                if (bytes[i + j] != plain[j]) { matched = false; break; }
            }
            assertFalse(matched, "Persisted column must contain ciphertext, not plaintext");
        }
        // Length sanity: IV (12) + plaintext + tag (16) — at least.
        assertTrue(bytes.length >= 12 + plain.length + 16,
            "Ciphertext must include IV + tag overhead");

        // Decrypting recovers the original secret.
        String roundTripped = cipher.decrypt(bytes);
        assertEquals(secret, roundTripped);
    }

    @Test
    void roundTripThroughRepository_preservesSecret() {
        String secret = "misp-api-key-deadbeef";
        IntegrationConfig stored = repository.saveAndFlush(
            new IntegrationConfig("MISP", "{\"url\":\"https://misp.example\"}",
                cipher.encrypt(secret)));
        IntegrationConfig reloaded = repository.findByIntegrationType("MISP").orElseThrow();
        assertEquals(stored.getId(), reloaded.getId());
        assertEquals(secret, cipher.decrypt(reloaded.getEncryptedCredentials()),
            "Decrypted secret must match original after repository round-trip");
    }
}
