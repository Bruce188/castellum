package io.castellum.graph;

/**
 * JGraphT vertex type for the attack graph. Identity is on {@code deviceId} (a Device PK).
 *
 * <p>Records auto-generate equals/hashCode on all components; only deviceId is identity-bearing
 * in practice (ipAddress is metadata for response surfacing). Two vertices with the same
 * deviceId but different ipAddress strings would compare unequal — by construction GraphBuilder
 * builds at most one vertex per Device row, so this case never arises.
 */
public record DeviceVertex(long deviceId, String ipAddress) {

    public DeviceVertex {
        if (deviceId <= 0) {
            throw new IllegalArgumentException("deviceId must be positive, got " + deviceId);
        }
    }
}
