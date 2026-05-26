package io.castellum.scan;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ScanSizeGuardTest {

    @Test
    void slash16_rejected() {
        ScanScopeTooLargeException ex = assertThrows(ScanScopeTooLargeException.class,
            () -> ScanSizeGuard.requireBoundedScope("10.0.0.0/16"));
        assertEquals(16, ex.getPrefix());
        assertEquals(22, ex.getMaxAllowedPrefix());
        assertTrue(ex.getMessage().contains("/16"));
        assertTrue(ex.getMessage().contains("65536"),
            "message must include actual host count: " + ex.getMessage());
    }

    @Test
    void slash21_rejected() {
        assertThrows(ScanScopeTooLargeException.class,
            () -> ScanSizeGuard.requireBoundedScope("10.0.0.0/21"));
    }

    @Test
    void slash22_accepted_boundary() {
        // /22 == 1024 hosts == the maximum permitted scope. Boundary case.
        assertDoesNotThrow(() -> ScanSizeGuard.requireBoundedScope("10.0.0.0/22"));
    }

    @Test
    void slash24_accepted() {
        assertDoesNotThrow(() -> ScanSizeGuard.requireBoundedScope("192.168.1.0/24"));
    }

    @Test
    void slash32_accepted() {
        assertDoesNotThrow(() -> ScanSizeGuard.requireBoundedScope("10.0.0.5/32"));
    }
}
