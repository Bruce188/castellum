package io.castellum.discovery;

/** A single neighbor observed by a discovery probe. */
public record DiscoveredNeighbor(
    String ipAddress,
    String macAddress,
    String hwType,
    String flags,
    String iface
) {}
