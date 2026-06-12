package io.castellum.scan;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link ScanSizeGuard#requireChunkableScope(String)} — the relaxed sizing policy
 * for the POST /api/scan intake. Ranges down to /16 are accepted (they will be
 * executed as sequential /22 chunks); wider than /16 still throws.
 *
 * <p>{@link ScanSizeGuard#requireBoundedScope(String)} keeps its strict /22 bound
 * for the other callers (ScanPolicyScheduler, ScanPolicyController,
 * ActiveNetworkDetector) — pinned here differentially, and its existing tests in
 * {@link ScanSizeGuardTest} stay untouched.
 */
class ScanSizeGuardChunkableTest {

    @Test
    void minChunkablePrefixConstant_is16() {
        assertEquals(16, ScanSizeGuard.MIN_CHUNKABLE_PREFIX);
    }

    @Test
    void slash24_accepted() {
        assertDoesNotThrow(() -> ScanSizeGuard.requireChunkableScope("192.168.1.0/24"));
    }

    @Test
    void slash22_accepted() {
        assertDoesNotThrow(() -> ScanSizeGuard.requireChunkableScope("10.0.0.0/22"));
    }

    @Test
    void slash20_accepted_willBeChunked() {
        assertDoesNotThrow(() -> ScanSizeGuard.requireChunkableScope("10.0.0.0/20"));
    }

    @Test
    void slash16_accepted_boundary() {
        assertDoesNotThrow(() -> ScanSizeGuard.requireChunkableScope("10.0.0.0/16"));
    }

    @Test
    void slash15_rejected_messageMentionsSlash16Ceiling() {
        ScanScopeTooLargeException ex = assertThrows(ScanScopeTooLargeException.class,
            () -> ScanSizeGuard.requireChunkableScope("10.0.0.0/15"));
        assertEquals(15, ex.getPrefix());
        assertTrue(ex.getMessage().contains("/16"),
            "message must mention the /16 ceiling for chunked scans: " + ex.getMessage());
    }

    @Test
    void slash8_rejected() {
        assertThrows(ScanScopeTooLargeException.class,
            () -> ScanSizeGuard.requireChunkableScope("10.0.0.0/8"));
    }

    /**
     * Differential pin: the strict policy is NOT relaxed — a /20 that the chunkable
     * policy accepts must still be rejected by requireBoundedScope.
     */
    @Test
    void boundedScope_remainsStrict_slash20StillRejected() {
        assertDoesNotThrow(() -> ScanSizeGuard.requireChunkableScope("10.0.0.0/20"));
        assertThrows(ScanScopeTooLargeException.class,
            () -> ScanSizeGuard.requireBoundedScope("10.0.0.0/20"));
    }
}
