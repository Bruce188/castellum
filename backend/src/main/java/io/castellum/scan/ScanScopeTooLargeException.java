package io.castellum.scan;

/**
 * Thrown when a scan-submission's CIDR prefix is shorter than
 * {@link ScanSizeGuard#MAX_ALLOWED_PREFIX}. Mapped to HTTP 400 by
 * {@code GlobalExceptionHandler}.
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
