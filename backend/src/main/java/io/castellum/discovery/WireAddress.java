package io.castellum.discovery;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Canonical wire-bytes → string IP-address converter for the discovery package.
 *
 * <p>Turns raw network-order address bytes (4 for IPv4, 16 for IPv6) into the literal
 * form ({@code "192.0.2.1"}, {@code "2001:db8::1"}) used as {@code ipAddress} on
 * {@link DiscoveredNeighbor}. Shared by {@link LldpDecoder} (management-address TLV)
 * and {@link CdpDecoder} (address-block entries).
 */
final class WireAddress {

    private WireAddress() {
        throw new UnsupportedOperationException("static utility");
    }

    /**
     * Converts raw address bytes to their literal string form, or null when the byte
     * count matches neither IP family — callers validate the declared length first,
     * so the null path is defensive only.
     */
    static String toLiteral(byte[] addr) {
        try {
            return InetAddress.getByAddress(addr).getHostAddress();
        } catch (UnknownHostException e) {
            return null; // wrong raw-address length — callers length-check beforehand
        }
    }
}
