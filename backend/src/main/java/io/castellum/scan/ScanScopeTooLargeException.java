package io.castellum.scan;

/**
 * Thrown when a CIDR's prefix is shorter than the applicable sizing tier:
 * {@link ScanSizeGuard#MAX_ALLOWED_PREFIX} (/22, strict — scheduler/policy and
 * per-chunk execution bound) or {@link ScanSizeGuard#MIN_CHUNKABLE_PREFIX}
 * (/16, chunked POST /api/scan intake ceiling). {@code maxAllowedPrefix}
 * carries whichever threshold the failing caller enforced. Mapped to HTTP 400
 * by {@code GlobalExceptionHandler}.
 */
public class ScanScopeTooLargeException extends RuntimeException {

    private final int prefix;
    private final int maxAllowedPrefix;

    public ScanScopeTooLargeException(int prefix, int maxAllowedPrefix, String message) {
        super(message);
        this.prefix = prefix;
        this.maxAllowedPrefix = maxAllowedPrefix;
    }

    public int getPrefix() { return prefix; }
    public int getMaxAllowedPrefix() { return maxAllowedPrefix; }
}
