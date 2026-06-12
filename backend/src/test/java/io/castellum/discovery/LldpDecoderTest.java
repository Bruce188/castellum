package io.castellum.discovery;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Frame-level tests for the real LLDP TLV decoder (slice 5).
 *
 * <p>Frames are assembled byte-by-byte with a small in-test TLV builder:
 * Ethernet header (dst 6 / src 6 / ethertype 2, big-endian), LLDPDU at offset 14
 * (18 for 802.1Q-tagged frames), TLV header of 2 bytes — type in the top 7 bits
 * of the first byte, 9-bit length spanning the low bit of the first byte and all
 * of the second.
 */
class LldpDecoderTest {

    private final LldpDecoder decoder = new LldpDecoder();

    private static final byte[] LLDP_MULTICAST_DST =
        {0x01, (byte) 0x80, (byte) 0xc2, 0x00, 0x00, 0x0e};
    private static final byte[] SOURCE_MAC = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    private static final byte[] CHASSIS_MAC =
        {(byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff};
    private static final byte[] PORT_MAC = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    private static final byte[] FD00_1 =
        {(byte) 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    // ────────────────────────────────────────────────────────────────────────
    // In-test TLV / frame builders
    // ────────────────────────────────────────────────────────────────────────

    /** TLV header: type in top 7 bits of b0, 9-bit length = (b0 & 0x01) << 8 | b1. */
    private static byte[] tlv(int type, byte[] value) {
        byte[] out = new byte[2 + value.length];
        out[0] = (byte) ((type << 1) | ((value.length >> 8) & 0x01));
        out[1] = (byte) (value.length & 0xFF);
        System.arraycopy(value, 0, out, 2, value.length);
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    /** Subtype byte followed by the payload (Chassis ID / Port ID value layout). */
    private static byte[] subtyped(int subtype, byte[] payload) {
        return concat(new byte[]{(byte) subtype}, payload);
    }

    /** Untagged Ethernet frame: dst + src + ethertype 0x88cc + LLDPDU at offset 14. */
    private static byte[] frame(byte[]... tlvs) {
        return concat(LLDP_MULTICAST_DST, SOURCE_MAC,
            new byte[]{(byte) 0x88, (byte) 0xcc}, concat(tlvs));
    }

    /** 802.1Q frame: TPID 0x8100 at 12-13, 2-byte TCI, real ethertype at 16, LLDPDU at 18. */
    private static byte[] vlanTaggedFrame(byte[]... tlvs) {
        return concat(LLDP_MULTICAST_DST, SOURCE_MAC,
            new byte[]{(byte) 0x81, 0x00},          // TPID
            new byte[]{0x00, 0x64},                 // TCI (VLAN 100)
            new byte[]{(byte) 0x88, (byte) 0xcc},   // real ethertype
            concat(tlvs));
    }

    private static byte[] chassisIdMac(byte[] mac) {
        return tlv(1, subtyped(4, mac));            // chassis subtype 4 = MAC address
    }

    private static byte[] chassisIdLocal(String id) {
        return tlv(1, subtyped(7, id.getBytes(StandardCharsets.UTF_8))); // 7 = locally assigned
    }

    private static byte[] portIdMac(byte[] mac) {
        return tlv(2, subtyped(3, mac));            // port subtype 3 = MAC address
    }

    private static byte[] portIdIfName(String name) {
        return tlv(2, subtyped(5, name.getBytes(StandardCharsets.UTF_8))); // 5 = interface name
    }

    private static byte[] ttl(int seconds) {
        return tlv(3, new byte[]{(byte) (seconds >> 8), (byte) (seconds & 0xFF)});
    }

    private static byte[] systemName(String name) {
        return tlv(5, name.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Management Address TLV: value[0] = mgmt-address-string length (subtype + addr bytes),
     * value[1] = address subtype (1 = IPv4, 2 = IPv6), address at value[2..], then interface
     * numbering subtype (1 byte) + interface number (4 bytes) + OID length 0 (all ignored).
     */
    private static byte[] mgmtAddress(int addrSubtype, byte[] addr) {
        return tlv(8, concat(
            new byte[]{(byte) (1 + addr.length), (byte) addrSubtype},
            addr,
            new byte[]{0x02, 0x00, 0x00, 0x00, 0x01, 0x00}));
    }

    private static byte[] endOfLldpdu() {
        return tlv(0, new byte[0]);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 1. Full frame — every supported TLV maps to its DiscoveredNeighbor slot
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_fullFrame_mapsAllFields() {
        byte[] f = frame(
            chassisIdMac(CHASSIS_MAC),
            portIdIfName("Gi0/1"),
            ttl(120),
            systemName("switch01"),
            mgmtAddress(1, new byte[]{(byte) 192, (byte) 168, 1, 10}),
            endOfLldpdu());

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        DiscoveredNeighbor n = result.get(0);
        assertThat(n.ipAddress()).isEqualTo("192.168.1.10");
        assertThat(n.macAddress())
            .as("chassis MAC must be lowercase colon-separated %%02x (ARP-reader format)")
            .isEqualTo("aa:bb:cc:dd:ee:ff");
        assertThat(n.hostname()).isEqualTo("switch01");
        assertThat(n.iface()).isEqualTo("eth0");
        assertThat(n.hwType()).isNull();
        assertThat(n.flags()).isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 2. No Management Address TLV — ipAddress null, mac + hostname still set
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_noMgmtAddressTlv_ipNullMacAndHostnameSet() {
        byte[] f = frame(
            chassisIdMac(CHASSIS_MAC),
            portIdIfName("Gi0/2"),
            ttl(120),
            systemName("switch01"),
            endOfLldpdu());

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        DiscoveredNeighbor n = result.get(0);
        assertThat(n.ipAddress()).isNull();
        assertThat(n.macAddress()).isEqualTo("aa:bb:cc:dd:ee:ff");
        assertThat(n.hostname()).isEqualTo("switch01");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 3. 802.1Q-tagged frame — decodes identically to the untagged one
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_vlanTaggedFrame_decodesIdentically() {
        byte[] f = vlanTaggedFrame(
            chassisIdMac(CHASSIS_MAC),
            portIdIfName("Gi0/1"),
            ttl(120),
            systemName("switch01"),
            mgmtAddress(1, new byte[]{(byte) 192, (byte) 168, 1, 10}),
            endOfLldpdu());

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        DiscoveredNeighbor n = result.get(0);
        assertThat(n.ipAddress()).isEqualTo("192.168.1.10");
        assertThat(n.macAddress()).isEqualTo("aa:bb:cc:dd:ee:ff");
        assertThat(n.hostname()).isEqualTo("switch01");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 4. Wrong ethertype — empty result, never throw
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_wrongEthertype_returnsEmpty() {
        byte[] ipv4Frame = concat(LLDP_MULTICAST_DST, SOURCE_MAC,
            new byte[]{0x08, 0x00},                  // ethertype 0x0800 = IPv4
            new byte[]{0x45, 0x00, 0x00, 0x14});     // arbitrary payload

        assertThat(decoder.decode(ipv4Frame, "eth0")).isEmpty();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 5. Truncated TLV — declared length overruns the buffer: stop parsing,
    //    keep the fields collected so far, never throw
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_truncatedTlv_keepsFieldsCollectedSoFar() {
        // Chassis MAC TLV is intact; the following System Name TLV declares length 200
        // but only 2 bytes of value follow.
        byte[] truncatedSysName = {(byte) (5 << 1), (byte) 200, 's', 'w'};
        byte[] f = concat(LLDP_MULTICAST_DST, SOURCE_MAC,
            new byte[]{(byte) 0x88, (byte) 0xcc},
            chassisIdMac(CHASSIS_MAC),
            truncatedSysName);

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        DiscoveredNeighbor n = result.get(0);
        assertThat(n.macAddress())
            .as("MAC collected before the overrunning TLV must be kept")
            .isEqualTo("aa:bb:cc:dd:ee:ff");
        assertThat(n.hostname())
            .as("the truncated System Name TLV must not contribute a hostname")
            .isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 6. Chassis subtype 7 (locally assigned) — MAC falls back to Port ID subtype 3
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_chassisLocallyAssigned_macFallsBackToPortId() {
        byte[] f = frame(
            chassisIdLocal("chassis-007"),
            portIdMac(PORT_MAC),
            ttl(120),
            endOfLldpdu());

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).macAddress())
            .as("port-ID MAC (subtype 3) is the fallback when chassis yields no MAC")
            .isEqualTo("11:22:33:44:55:66");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 7. IPv6-only management address — IPv6 string form via InetAddress
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_ipv6OnlyMgmtAddress_mapsIpv6StringForm() throws Exception {
        byte[] f = frame(
            chassisIdMac(CHASSIS_MAC),
            ttl(120),
            mgmtAddress(2, FD00_1),
            endOfLldpdu());

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).ipAddress())
            .isEqualTo(InetAddress.getByAddress(FD00_1).getHostAddress());
    }

    // ────────────────────────────────────────────────────────────────────────
    // 8. IPv4 + IPv6 management TLVs — the first IPv4 wins, even when IPv6 came first
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_ipv4AndIpv6MgmtAddresses_ipv4Wins() {
        byte[] f = frame(
            chassisIdMac(CHASSIS_MAC),
            ttl(120),
            mgmtAddress(2, FD00_1),                      // IPv6 arrives first
            mgmtAddress(1, new byte[]{10, 1, 2, 3}),     // IPv4 must still win
            endOfLldpdu());

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).ipAddress()).isEqualTo("10.1.2.3");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 9. TTL=0 shutdown frame — still decoded (the device demonstrably exists)
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_ttlZeroShutdownFrame_stillDecoded() {
        byte[] f = frame(
            chassisIdMac(CHASSIS_MAC),
            ttl(0),
            endOfLldpdu());

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).macAddress()).isEqualTo("aa:bb:cc:dd:ee:ff");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 10. Empty / sub-14-byte frame — empty result, never throw
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_emptyOrTooShortFrame_returnsEmpty() {
        assertThat(decoder.decode(new byte[0], "eth0")).isEmpty();
        assertThat(decoder.decode(new byte[13], "eth0")).isEmpty();
    }
}
