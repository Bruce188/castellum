package io.castellum.discovery;

/**
 * A single neighbor observed by a discovery probe.
 *
 * <p>The {@code hostname} slot was added in fix/discovery-polish so that
 * {@link MdnsProbe} can propagate the {@code info.getServer()} value end-to-end into
 * {@link io.castellum.domain.Device#getHostname()}. ARP-source readers
 * (Linux/Windows/Mac) pass {@code null} for hostname.
 */
public record DiscoveredNeighbor(
    String ipAddress,
    String macAddress,
    String hwType,
    String flags,
    String iface,
    String hostname
) {}
