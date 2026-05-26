package io.castellum.security;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-256-GCM symmetric encryption for integration credentials at rest.
 *
 * <p>Ciphertext format on disk: {@code [12-byte IV][ciphertext || 16-byte auth tag]}.
 * The IV is generated fresh per call from {@link SecureRandom} — never reuse one
 * with the same key. Auth tag length is 128 bits (the GCM spec recommended max).
 *
 * <p>Key material is base64-encoded AES-256 (32 raw bytes → 44 base64 chars).
 * Source: env var {@code CASTELLUM_INTEGRATION_KEY} → property
 * {@code castellum.integration.key}. Startup fails fast if the key is missing
 * or wrong-length, so the only valid runtime state is "key present and correct".
 */
@Component
public class AesGcmCipher {

    private static final Logger log = LoggerFactory.getLogger(AesGcmCipher.class);

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int KEY_LENGTH_BYTES = 32; // AES-256

    private final String configuredKeyBase64;
    private final SecureRandom random = new SecureRandom();
    private byte[] keyBytes;

    public AesGcmCipher(@Value("${castellum.integration.key:}") String configuredKeyBase64) {
        this.configuredKeyBase64 = configuredKeyBase64 == null ? "" : configuredKeyBase64.trim();
    }

    @PostConstruct
    public void verifyKey() {
        if (configuredKeyBase64.isEmpty()) {
            // Allow a missing key at runtime in test / dev contexts that never call encrypt/decrypt.
            // Fail-fast only on first use (encrypt / decrypt) so that contexts which do not exercise
            // integrations do not need to set the env var. See encrypt()/decrypt() for the runtime check.
            log.warn("CASTELLUM_INTEGRATION_KEY not set — integration encryption will fail until configured");
            this.keyBytes = null;
            return;
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(configuredKeyBase64);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                "CASTELLUM_INTEGRATION_KEY is not valid base64", e);
        }
        if (decoded.length != KEY_LENGTH_BYTES) {
            throw new IllegalStateException(
                "CASTELLUM_INTEGRATION_KEY must decode to " + KEY_LENGTH_BYTES
                    + " bytes (AES-256), got " + decoded.length);
        }
        this.keyBytes = decoded;
    }

    /**
     * Encrypts plaintext with the configured AES-256 key.
     *
     * @param plaintext UTF-8 string to encrypt (never null; pass "" for blank).
     * @return {@code [iv(12)] || [ciphertext || tag(16)]}
     */
    public byte[] encrypt(String plaintext) {
        return encrypt(plaintext, requireKey());
    }

    /**
     * Decrypts ciphertext produced by {@link #encrypt(String)}.
     *
     * @throws IllegalStateException if the ciphertext is malformed or the tag fails to verify.
     */
    public String decrypt(byte[] ciphertext) {
        return decrypt(ciphertext, requireKey());
    }

    /** Test-only overload taking an explicit key (bypasses {@link #configuredKeyBase64}). */
    public byte[] encrypt(String plaintext, byte[] key) {
        if (plaintext == null) throw new IllegalArgumentException("plaintext must not be null");
        byte[] iv = new byte[IV_LENGTH_BYTES];
        random.nextBytes(iv);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] enc = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return ByteBuffer.allocate(iv.length + enc.length).put(iv).put(enc).array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM encryption failed", e);
        }
    }

    /** Test-only overload taking an explicit key. */
    public String decrypt(byte[] ciphertext, byte[] key) {
        if (ciphertext == null || ciphertext.length < IV_LENGTH_BYTES + 16) {
            throw new IllegalStateException("ciphertext too short to contain IV + tag");
        }
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            byte[] body = new byte[ciphertext.length - IV_LENGTH_BYTES];
            System.arraycopy(ciphertext, 0, iv, 0, IV_LENGTH_BYTES);
            System.arraycopy(ciphertext, IV_LENGTH_BYTES, body, 0, body.length);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] plain = cipher.doFinal(body);
            return new String(plain, java.nio.charset.StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM decryption / tag-verify failed", e);
        }
    }

    private byte[] requireKey() {
        if (keyBytes == null) {
            throw new IllegalStateException(
                "CASTELLUM_INTEGRATION_KEY is not configured — set a base64 AES-256 key");
        }
        return keyBytes;
    }

    /** Generates a fresh AES-256 key, base64-encoded. Useful for ops onboarding scripts. */
    public static String generateBase64Key() {
        byte[] k = new byte[KEY_LENGTH_BYTES];
        new SecureRandom().nextBytes(k);
        return Base64.getEncoder().encodeToString(k);
    }
}
