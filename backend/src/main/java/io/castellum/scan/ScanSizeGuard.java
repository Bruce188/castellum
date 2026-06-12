package io.castellum.scan;

/**
 * Two-tier sizing policy for scan scopes.
 *
 * <p><b>Strict tier — {@link #requireBoundedScope}.</b> Caps a single nmap
 * invocation at /22 (1024 hosts): at the F11 fix's {@code --host-timeout 30s},
 * anything wider would blow the 5-min outer cap against a fully-unresponsive
 * subnet. This bound governs scheduler policies, the active-network detector,
 * and is the per-chunk invariant of the execution engine.
 *
 * <p><b>Chunkable tier — {@link #requireChunkableScope}.</b> The POST /api/scan
 * intake accepts CIDRs down to /16 (65536 hosts); execution splits them into
 * sequential /22 chunks ({@code CidrChunker}), so every individual nmap run
 * still satisfies the strict tier's per-run budget.
 */
public final class ScanSizeGuard {

    /** Minimum prefix length permitted (inclusive). /22 = 1024 hosts. */
    public static final int MAX_ALLOWED_PREFIX = 22;

    /**
     * Minimum prefix length permitted for chunked (operator-submitted) scans.
     * A /16 (65536 hosts) executes as 64 sequential /22 chunks, each individually
     * within the strict bound — so the intake ceiling can relax to /16 without
     * any single nmap invocation exceeding the per-run budget.
     */
    public static final int MIN_CHUNKABLE_PREFIX = 16;

    private ScanSizeGuard() {}

    /**
     * Throws {@link ScanScopeTooLargeException} if the CIDR's prefix is below
     * {@link #MAX_ALLOWED_PREFIX}. Assumes the input has already passed
     * {@link CidrValidator#isValid(String)} structural checks.
     */
    public static void requireBoundedScope(String cidr) {
        int prefix = parsePrefix(cidr);
        if (prefix < MAX_ALLOWED_PREFIX) {
            long hostCount = 1L << (32 - prefix);
            throw new ScanScopeTooLargeException(prefix, MAX_ALLOWED_PREFIX,
                "Scope too large: a /" + prefix + " contains " + hostCount
                    + " hosts; please scope to /" + MAX_ALLOWED_PREFIX + " or smaller.");
        }
    }

    /**
     * Relaxed sizing policy for the chunked POST /api/scan intake: CIDRs down to /16
     * are accepted (they will be executed as sequential /22 chunks); anything wider
     * than /16 throws {@link ScanScopeTooLargeException}. Assumes the input has
     * already passed {@link CidrValidator#isValid(String)} structural checks.
     */
    public static void requireChunkableScope(String cidr) {
        int prefix = parsePrefix(cidr);
        if (prefix < MIN_CHUNKABLE_PREFIX) {
            long hostCount = 1L << (32 - prefix);
            throw new ScanScopeTooLargeException(prefix, MIN_CHUNKABLE_PREFIX,
                "Scope too large: a /" + prefix + " contains " + hostCount
                    + " hosts; chunked scans support /" + MIN_CHUNKABLE_PREFIX + " or smaller.");
        }
    }

    private static int parsePrefix(String cidr) {
        int slash = cidr.lastIndexOf('/');
        return Integer.parseInt(cidr.substring(slash + 1));
    }
}
