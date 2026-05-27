package io.castellum.web.dto;

/**
 * Response DTO for {@code GET /api/discovery/active-cidr}.
 *
 * <p>All string fields are nullable. When the host is not Linux (no
 * {@code /proc/net/route}) or when no default route is present, the endpoint
 * returns the documented <strong>empty shape</strong>:
 * {@code { "prefix": 0 }} — all other fields absent/null.
 *
 * <p>The {@code note} field is non-null only when the detected prefix was wider
 * than {@link io.castellum.scan.ScanSizeGuard#MAX_ALLOWED_PREFIX} and was
 * narrowed automatically. The UI should surface this as an inline hint.
 *
 * <p>Empty shape: {@code { iface: null, cidr: null, ipAddress: null, prefix: 0, note: null }}.
 */
public record ActiveCidrDto(
    /** Interface name carrying the default route, e.g. {@code "eth6"}. Null on empty detection. */
    String iface,
    /** Detected CIDR, e.g. {@code "192.168.68.0/22"}. Null on empty detection. */
    String cidr,
    /** First IPv4 address on the detected interface. Null when the resolver found none. */
    String ipAddress,
    /** Network prefix length after any clamp. {@code 0} on empty detection. */
    int prefix,
    /**
     * Human-readable note when the prefix was narrowed to
     * {@link io.castellum.scan.ScanSizeGuard#MAX_ALLOWED_PREFIX}. Null otherwise.
     */
    String note
) {}
