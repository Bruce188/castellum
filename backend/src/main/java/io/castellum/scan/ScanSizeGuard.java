package io.castellum.scan;

/**
 * Rejects CIDR ranges whose host count would blow the outer scan timeout.
 *
 * <p>An nmap sweep against a /16 (65k hosts) at the F11 fix's
 * {@code --host-timeout 30s} would need ~32 wall-clock minutes against a
 * fully-unresponsive subnet — far above the 5-min outer cap. Capping at /22
 * (1024 hosts) keeps worst-case latency tractable while still letting an
 * operator scan typical small lab segments.
 */
public final class ScanSizeGuard {

    /** Minimum prefix length permitted (inclusive). /22 = 1024 hosts. */
    public static final int MAX_ALLOWED_PREFIX = 22;

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

    private static int parsePrefix(String cidr) {
        int slash = cidr.lastIndexOf('/');
        return Integer.parseInt(cidr.substring(slash + 1));
    }
}
