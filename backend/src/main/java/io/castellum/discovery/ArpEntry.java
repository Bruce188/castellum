package io.castellum.discovery;

/**
 * A single entry parsed from {@code /proc/net/arp}.
 *
 * <p>Fields correspond directly to the kernel ARP cache columns:
 * IP address, hardware type, flags, hardware address (MAC), and device (interface).
 */
public record ArpEntry(
    String ip,
    String mac,
    String hwType,
    String flags,
    String iface
) {}
