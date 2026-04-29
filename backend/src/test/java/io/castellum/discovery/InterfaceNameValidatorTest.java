package io.castellum.discovery;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InterfaceNameValidatorTest {

    @Test
    void requireValid_acceptsKnownModernNames() {
        // Should not throw for valid Linux interface names
        for (String name : new String[]{"eth0", "enp0s3", "wlp2s0", "mgmt0", "lan-eth0", "lo", "docker0"}) {
            assertDoesNotThrow(() -> InterfaceNameValidator.requireValid(name),
                "Expected valid interface name: " + name);
        }
    }

    @Test
    void requireValid_rejectsShellInjection() {
        for (String bad : new String[]{
                "eth0;rm -rf /",
                "eth0 && id",
                "eth0|cat",
                "eth 0",
                "eth0`id`",
                "$(id)"
        }) {
            assertThrows(IllegalArgumentException.class,
                () -> InterfaceNameValidator.requireValid(bad),
                "Expected rejection of shell-injection attempt: " + bad);
        }
    }

    @Test
    void requireValid_rejectsLengthOver16() {
        // 17 characters — one over IFNAMSIZ
        String longName = "aaaaaaaaaaaaaaaaa";
        assertEquals(17, longName.length());
        assertThrows(IllegalArgumentException.class,
            () -> InterfaceNameValidator.requireValid(longName));
    }

    @Test
    void requireValid_rejectsEmptyAndNull() {
        assertThrows(IllegalArgumentException.class,
            () -> InterfaceNameValidator.requireValid(""));
        assertThrows(IllegalArgumentException.class,
            () -> InterfaceNameValidator.requireValid(null));
    }
}
