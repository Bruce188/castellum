package io.castellum.discovery;

/**
 * Bucket the IPv4 origin of a {@link Discovery} into for UI presentation.
 *
 * <p>Used by {@link DiscoveryScopeClassifier#classify(String)} to label each
 * {@code Device} so the operator can visually distinguish home-LAN devices
 * from Docker-bridge siblings, IPv4 link-local APIPA leakage, loopback, and
 * routable public IPs. Buckets are persisted on the {@code Device} entity
 * (column {@code discovery_scope}, see Flyway V17) — never filtered out at
 * the discovery layer per the project's "find everything, label rather than
 * filter" principle. One retention exception applies after discovery:
 * {@link #PUBLIC}-scope rows from passive observation sources are subject to
 * TTL-based pruning — see {@link DevicePruneService}.
 */
public enum DiscoveryScope {
    HOME,
    DOCKER_BRIDGE,
    LINK_LOCAL,
    LOOPBACK,
    PUBLIC
}
