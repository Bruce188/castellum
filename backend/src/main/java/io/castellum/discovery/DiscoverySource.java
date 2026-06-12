package io.castellum.discovery;

/**
 * Sources for passive network discovery.
 *
 * <p>All values represent <strong>read-only</strong> probes — no traffic is emitted on the wire.
 *
 * <p>{@link #LLDP} and {@link #CDP} require both the corresponding feature flag
 * (<code>castellum.discovery.lldp.enabled</code> / <code>castellum.discovery.cdp.enabled</code>)
 * AND a managed-switch infrastructure advertising LLDP or CDP frames. Both run a live
 * promiscuous capture ({@link LldpCapture} / {@link CdpCapture}) feeding a frame-level TLV
 * decoder ({@link LldpDecoder} / {@link CdpDecoder}); a neighbor without a management
 * address persists as a MAC-keyed placeholder device — see the {@code @Service} Javadocs.
 */
public enum DiscoverySource {
    ARP,
    MDNS,
    PCAP,
    LLDP,
    CDP,
    /** Active OT/ICS fingerprint probe (Modbus, DNP3, S7comm, BACnet). */
    OT_PROBE,
    /** Active nmap-based network scan (PING_SWEEP, SERVICE_DETECT, OS_FINGERPRINT). */
    NMAP_SCAN,
    /**
     * Local Docker daemon inventory via the {@code docker} CLI ({@code docker ps} +
     * {@code docker inspect}). Unlike the wire-emitting sources above, this reads the
     * host's own container runtime — no network traffic is generated.
     */
    DOCKER,
    /**
     * Host connection-table scan of {@code /proc/net/{tcp,tcp6,udp,udp6}} — the remote
     * endpoints of the host's own established TCP and connected UDP sockets. Like
     * {@link #DOCKER}, this is a pure local read with no wire traffic; it is the source
     * that surfaces off-network (PUBLIC-scope) peers on any host with outbound connections.
     */
    CONN_TABLE,
    /**
     * Default-route gateway extracted from {@code /proc/net/route}. Read-only,
     * single-neighbor probe that guarantees the router itself lands in the inventory.
     */
    GATEWAY
}
