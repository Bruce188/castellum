package io.castellum.discovery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * LLDP (IEEE 802.1AB) frame decoder.
 *
 * <p>Parses a full Ethernet frame carrying an LLDPDU (ethertype {@code 0x88cc}, optionally
 * behind one 802.1Q tag) into at most one {@link DiscoveredNeighbor}:
 * <ul>
 *   <li>Chassis ID subtype 4 (MAC) → {@code macAddress}, lowercase colon-separated
 *       {@code %02x} (matches the ARP-reader format so MAC keys collide correctly in
 *       {@link DeviceUpsertService});</li>
 *   <li>Port ID subtype 3 (MAC) → fallback {@code macAddress} when the chassis yields none;</li>
 *   <li>System Name → {@code hostname} (trimmed, blank → null);</li>
 *   <li>Management Address → {@code ipAddress}: the first IPv4 wins, else the first IPv6;</li>
 *   <li>TTL is ignored — TTL=0 shutdown frames are still decoded (the device demonstrably
 *       exists).</li>
 * </ul>
 *
 * <p>Malformed input never throws: a wrong ethertype or a sub-14-byte frame yields an empty
 * list, and a TLV whose declared length overruns the buffer ends parsing while keeping the
 * fields collected so far.
 */
@Service
public class LldpDecoder {

    private static final Logger log = LoggerFactory.getLogger(LldpDecoder.class);

    private static final int ETHERTYPE_LLDP = 0x88cc;

    private static final int TLV_END = 0;
    private static final int TLV_CHASSIS_ID = 1;
    private static final int TLV_PORT_ID = 2;
    private static final int TLV_SYSTEM_NAME = 5;
    private static final int TLV_MGMT_ADDRESS = 8;

    private static final int CHASSIS_SUBTYPE_MAC = 4;
    private static final int PORT_SUBTYPE_MAC = 3;
    private static final int MGMT_ADDR_SUBTYPE_IPV4 = 1;
    private static final int MGMT_ADDR_SUBTYPE_IPV6 = 2;

    public List<DiscoveredNeighbor> decode(byte[] frame, String iface) {
        if (frame == null || frame.length < 14) {
            return List.of();
        }
        EtherFraming framing = EtherFraming.of(frame);
        if (framing == null || framing.typeOrLength() != ETHERTYPE_LLDP) {
            return List.of(); // not the LLDP ethertype
        }
        int lldpStart = framing.payloadStart();

        String mac = null;
        String fallbackMac = null;
        String hostname = null;
        String ipv4 = null;
        String ipv6 = null;

        int offset = lldpStart;
        while (offset + 2 <= frame.length) {
            int b0 = frame[offset] & 0xFF;
            int b1 = frame[offset + 1] & 0xFF;
            int type = (b0 >> 1) & 0x7F;
            int length = ((b0 & 0x01) << 8) | b1;
            if (type == TLV_END) {
                break;
            }
            int valueStart = offset + 2;
            if (valueStart + length > frame.length) {
                break; // declared length overruns the buffer — keep fields so far
            }
            // Value bytes are only materialized for consumed TLV types — ignored TLVs
            // (TTL, port description, capabilities, …) cost no allocation.
            switch (type) {
                case TLV_CHASSIS_ID -> {
                    if (mac == null && length >= 7 && (frame[valueStart] & 0xFF) == CHASSIS_SUBTYPE_MAC) {
                        mac = MacFormat.format(frame, valueStart + 1);
                    }
                }
                case TLV_PORT_ID -> {
                    if (fallbackMac == null && length >= 7 && (frame[valueStart] & 0xFF) == PORT_SUBTYPE_MAC) {
                        fallbackMac = MacFormat.format(frame, valueStart + 1);
                    }
                }
                case TLV_SYSTEM_NAME -> {
                    if (hostname == null) {
                        String name = new String(frame, valueStart, length, StandardCharsets.UTF_8).trim();
                        hostname = name.isEmpty() ? null : name;
                    }
                }
                case TLV_MGMT_ADDRESS -> {
                    byte[] value = Arrays.copyOfRange(frame, valueStart, valueStart + length);
                    logUnusualMgmtAddress(value);
                    // Each TLV carries one family; first IPv4 wins downstream, else first IPv6.
                    if (ipv4 == null) {
                        ipv4 = parseMgmtAddress(value, MGMT_ADDR_SUBTYPE_IPV4, 4);
                    }
                    if (ipv6 == null) {
                        ipv6 = parseMgmtAddress(value, MGMT_ADDR_SUBTYPE_IPV6, 16);
                    }
                }
                default -> { /* TTL and all other TLVs ignored */ }
            }
            offset = valueStart + length;
        }

        if (mac == null) {
            mac = fallbackMac;
        }
        String ip = ipv4 != null ? ipv4 : ipv6;
        if (mac == null && ip == null && hostname == null) {
            return List.of();
        }
        return List.of(new DiscoveredNeighbor(ip, mac, null, null, iface, hostname));
    }

    /**
     * Management Address TLV: value[0] = mgmt-address-string length (subtype byte + address
     * bytes), value[1] = address subtype, address at value[2..]. Returns the converted
     * address only when the subtype and declared address length match the expected family;
     * the remainder of the TLV (interface numbering, OID) is ignored.
     */
    private static String parseMgmtAddress(byte[] value, int wantSubtype, int wantAddrLen) {
        if (value.length < 2) {
            return null;
        }
        int addrStringLen = value[0] & 0xFF;
        int subtype = value[1] & 0xFF;
        int addrLen = addrStringLen - 1;
        if (subtype != wantSubtype || addrLen != wantAddrLen || 2 + addrLen > value.length) {
            return null;
        }
        return WireAddress.toLiteral(Arrays.copyOfRange(value, 2, 2 + addrLen));
    }

    /**
     * Diagnostic only — fires when a management-address TLV declares an IPv4/IPv6 subtype
     * whose address length matches neither family's wire size (4 or 16). Such a TLV is
     * silently skipped by {@link #parseMgmtAddress}; a debug line keeps the malformed frame
     * observable without changing decode behavior. Normal cross-family parse misses (an
     * IPv4 TLV legitimately failing the IPv6 check) do not log.
     */
    private static void logUnusualMgmtAddress(byte[] value) {
        if (value.length < 2) {
            return;
        }
        int subtype = value[1] & 0xFF;
        int addrLen = (value[0] & 0xFF) - 1;
        if ((subtype == MGMT_ADDR_SUBTYPE_IPV4 && addrLen != 4)
                || (subtype == MGMT_ADDR_SUBTYPE_IPV6 && addrLen != 16)) {
            log.debug("LLDP management-address TLV with unexpected address length: subtype={} addrLen={}",
                subtype, addrLen);
        }
    }
}
