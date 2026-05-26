package io.castellum.discovery;

/**
 * Sources for passive network discovery.
 *
 * <p>All values represent <strong>read-only</strong> probes — no traffic is emitted on the wire.
 *
 * <p>{@link #LLDP} and {@link #CDP} require both the corresponding feature flag
 * (<code>castellum.discovery.lldp.enabled</code> / <code>castellum.discovery.cdp.enabled</code>)
 * AND a managed-switch infrastructure advertising LLDP-MED or CDP frames. The decoders ship as
 * designed-but-untested skeletons that throw {@link UnsupportedOperationException} when invoked —
 * see the corresponding {@code @Service} Javadocs.
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
    NMAP_SCAN
}
