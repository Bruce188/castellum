package io.castellum.scan;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ScanTypeTest {

    @Test
    void threeValues() {
        assertEquals(3, ScanType.values().length);
    }

    @Test
    void allArgvNonEmptyAndClean() {
        for (ScanType type : ScanType.values()) {
            assertNotNull(type.argv());
            assertFalse(type.argv().isEmpty(), type + " argv should not be empty");
            for (String token : type.argv()) {
                assertFalse(token.contains(" "), token + " contains space");
                assertFalse(token.contains(";"), token + " contains semicolon");
                assertFalse(token.contains("&"), token + " contains ampersand");
                assertFalse(token.contains("|"), token + " contains pipe");
                assertFalse(token.contains("$"), token + " contains dollar");
                assertFalse(token.contains("`"), token + " contains backtick");
            }
        }
    }

    @Test
    void valueOfPingSweepSucceeds() {
        assertEquals(ScanType.PING_SWEEP, ScanType.valueOf("PING_SWEEP"));
    }

    @Test
    void valueOfInvalidThrows() {
        assertThrows(IllegalArgumentException.class, () -> ScanType.valueOf("FOO"));
    }

    @Test
    void enumeratesPorts_trueForServiceDetectAndOsFingerprint() {
        assertTrue(ScanType.SERVICE_DETECT.enumeratesPorts(),
            "SERVICE_DETECT must enumerate ports");
        assertTrue(ScanType.OS_FINGERPRINT.enumeratesPorts(),
            "OS_FINGERPRINT must enumerate ports");
    }

    @Test
    void enumeratesPorts_falseForPingSweep() {
        assertFalse(ScanType.PING_SWEEP.enumeratesPorts(),
            "PING_SWEEP must NOT enumerate ports");
    }

    @Test
    void defaultHostTimeout_nonBlankAndCleanForAllTypes() {
        for (ScanType type : ScanType.values()) {
            String timeout = type.defaultHostTimeout();
            assertNotNull(timeout, type + " defaultHostTimeout should not be null");
            assertFalse(timeout.isBlank(), type + " defaultHostTimeout should not be blank");
            assertFalse(timeout.contains(" "), timeout + " contains space");
            assertFalse(timeout.contains(";"), timeout + " contains semicolon");
            assertFalse(timeout.contains("&"), timeout + " contains ampersand");
            assertFalse(timeout.contains("|"), timeout + " contains pipe");
            assertFalse(timeout.contains("$"), timeout + " contains dollar");
            assertFalse(timeout.contains("`"), timeout + " contains backtick");
        }
    }

    @Test
    void defaultHostTimeout_pingSweepShorterThanServiceDetect() {
        int pingSweepSeconds = parseLeadingInt(ScanType.PING_SWEEP.defaultHostTimeout());
        int serviceDetectSeconds = parseLeadingInt(ScanType.SERVICE_DETECT.defaultHostTimeout());
        assertTrue(pingSweepSeconds < serviceDetectSeconds,
            "PING_SWEEP timeout (" + pingSweepSeconds + ") must be shorter than SERVICE_DETECT timeout (" + serviceDetectSeconds + ")");
    }

    private static int parseLeadingInt(String token) {
        // e.g. "30s" → 30, "180s" → 180
        StringBuilder digits = new StringBuilder();
        for (char c : token.toCharArray()) {
            if (Character.isDigit(c)) digits.append(c);
            else break;
        }
        return Integer.parseInt(digits.toString());
    }
}
