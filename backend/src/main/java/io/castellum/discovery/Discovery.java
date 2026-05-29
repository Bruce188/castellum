package io.castellum.discovery;

import java.time.Instant;
import java.util.Objects;

/** A single observation from a passive-discovery probe. */
public record Discovery(
    String ipAddress,
    String macAddress,
    String hostname,
    DiscoverySource source,
    Instant observedAt,
    String iface,
    boolean publishesHostPort
) {
    public Discovery {
        Objects.requireNonNull(ipAddress, "ipAddress must not be null");
        if (ipAddress.isBlank()) {
            throw new IllegalArgumentException("ipAddress must not be blank");
        }
        Objects.requireNonNull(source, "source must not be null");
        Objects.requireNonNull(observedAt, "observedAt must not be null");
    }
}
