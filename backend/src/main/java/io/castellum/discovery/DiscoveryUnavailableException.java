package io.castellum.discovery;

/**
 * Checked exception signalling that a discovery source could not be queried — typically because
 * a required capability is missing (no {@code CAP_NET_RAW}, {@code libpcap} unavailable,
 * {@code /proc/net/arp} not readable) or the underlying probe threw a transport error.
 *
 * <p>Carries an optional {@code sweepId} so the caller can correlate the failure with a
 * {@code discovery_sweep} row created via {@link DiscoverySweepRecorder}.
 */
public class DiscoveryUnavailableException extends Exception {

    private final Long sweepId;

    public DiscoveryUnavailableException(String message) {
        this(message, null, null);
    }

    public DiscoveryUnavailableException(String message, Throwable cause) {
        this(message, cause, null);
    }

    public DiscoveryUnavailableException(String message, Throwable cause, Long sweepId) {
        super(message, cause);
        this.sweepId = sweepId;
    }

    public Long getSweepId() {
        return sweepId;
    }
}
