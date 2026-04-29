package io.castellum.discovery;

/**
 * Sources for passive network discovery.
 *
 * <p>All values represent <strong>read-only</strong> probes — no traffic is emitted on the wire.
 *
 * <p>{@link #LLDP_UNTESTED} and {@link #CDP_UNTESTED} require both the corresponding
 * feature flag (<code>castellum.discovery.lldp.enabled</code> /
 * <code>castellum.discovery.cdp.enabled</code>) AND a managed-switch infrastructure
 * advertising LLDP-MED or CDP frames. The decoders ship as designed-but-untested
 * skeletons that throw {@link UnsupportedOperationException} when invoked.
 */
public enum DiscoverySource {
    ARP,
    MDNS,
    PCAP,
    LLDP_UNTESTED,
    CDP_UNTESTED
}
