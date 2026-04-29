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
}
