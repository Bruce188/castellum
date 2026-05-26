package io.castellum.security;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class AesGcmCipherTest {

    private byte[] freshKey() {
        byte[] k = new byte[32];
        new SecureRandom().nextBytes(k);
        return k;
    }

    private AesGcmCipher cipherWithKey(byte[] key) {
        AesGcmCipher c = new AesGcmCipher(Base64.getEncoder().encodeToString(key));
        c.verifyKey();
        return c;
    }

    @Test
    void roundTrip_preservesPlaintext() {
        byte[] key = freshKey();
        AesGcmCipher cipher = cipherWithKey(key);
        String plaintext = "super-secret-taxii-password-!@#$%";
        byte[] enc = cipher.encrypt(plaintext);
        assertNotNull(enc);
        // 12-byte IV + ciphertext + 16-byte tag must equal at least 12 + plaintext + 16
        assertTrue(enc.length >= 12 + plaintext.getBytes(StandardCharsets.UTF_8).length + 16,
            "ciphertext length must include IV (12) + tag (16) overhead");
        // Plaintext bytes must NOT appear in ciphertext (rules out the encrypt being a no-op).
        byte[] plainBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i <= enc.length - plainBytes.length; i++) {
            boolean matched = true;
            for (int j = 0; j < plainBytes.length; j++) {
                if (enc[i + j] != plainBytes[j]) { matched = false; break; }
            }
            assertFalse(matched, "plaintext bytes must not appear contiguously in ciphertext");
        }
        assertEquals(plaintext, cipher.decrypt(enc));
    }

    @Test
    void roundTrip_handlesEmptyString() {
        byte[] key = freshKey();
        AesGcmCipher cipher = cipherWithKey(key);
        byte[] enc = cipher.encrypt("");
        assertEquals("", cipher.decrypt(enc));
    }

    @Test
    void freshIvPerEncrypt_producesDifferentCiphertextEachTime() {
        byte[] key = freshKey();
        AesGcmCipher cipher = cipherWithKey(key);
        byte[] a = cipher.encrypt("same-plaintext");
        byte[] b = cipher.encrypt("same-plaintext");
        assertFalse(java.util.Arrays.equals(a, b),
            "Two encryptions of the same plaintext must differ (fresh IV per call)");
    }

    @Test
    void decryptingWithWrongKey_fails() {
        byte[] k1 = freshKey();
        byte[] k2 = freshKey();
        AesGcmCipher c1 = cipherWithKey(k1);
        AesGcmCipher c2 = cipherWithKey(k2);
        byte[] enc = c1.encrypt("payload");
        assertThrows(IllegalStateException.class, () -> c2.decrypt(enc));
    }

    @Test
    void tamperedCiphertext_fails() {
        byte[] key = freshKey();
        AesGcmCipher cipher = cipherWithKey(key);
        byte[] enc = cipher.encrypt("tamper-me");
        // Flip a bit in the tag region (last 16 bytes) to trigger auth-fail.
        enc[enc.length - 1] ^= 0x01;
        assertThrows(IllegalStateException.class, () -> cipher.decrypt(enc));
    }

    @Test
    void missingKey_failsOnUse() {
        AesGcmCipher cipher = new AesGcmCipher("");
        cipher.verifyKey();
        assertThrows(IllegalStateException.class, () -> cipher.encrypt("anything"));
    }

    @Test
    void wrongKeyLength_failsAtVerify() {
        // 16-byte key (AES-128) — we require AES-256 (32 bytes).
        String b64 = Base64.getEncoder().encodeToString(new byte[16]);
        AesGcmCipher cipher = new AesGcmCipher(b64);
        assertThrows(IllegalStateException.class, cipher::verifyKey);
    }

    @Test
    void invalidBase64_failsAtVerify() {
        AesGcmCipher cipher = new AesGcmCipher("!!!not-base64-at-all!!!");
        assertThrows(IllegalStateException.class, cipher::verifyKey);
    }

    @Test
    void truncatedCiphertext_fails() {
        byte[] key = freshKey();
        AesGcmCipher cipher = cipherWithKey(key);
        byte[] enc = cipher.encrypt("payload");
        byte[] truncated = java.util.Arrays.copyOf(enc, 10); // shorter than IV+tag
        assertThrows(IllegalStateException.class, () -> cipher.decrypt(truncated));
    }

    @Test
    void generateBase64Key_producesUsableKey() {
        String b64 = AesGcmCipher.generateBase64Key();
        AesGcmCipher cipher = new AesGcmCipher(b64);
        cipher.verifyKey();
        byte[] enc = cipher.encrypt("hello");
        assertEquals("hello", cipher.decrypt(enc));
    }
}
