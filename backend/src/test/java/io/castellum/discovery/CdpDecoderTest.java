package io.castellum.discovery;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/**
 * Frame-level tests for the real CDP TLV decoder (slice 6).
 *
 * <p>CDP is not an ethertype protocol — it rides IEEE 802.3 frames with LLC/SNAP
 * encapsulation. Frames are assembled byte-by-byte with in-test builders:
 * 802.3 header (dst 6 / src 6 / big-endian length 2), LLC {@code AA AA 03} at
 * offset 14, SNAP OUI {@code 00 00 0C} + protocol ID {@code 0x2000} at 17-21,
 * the 4-byte CDP header (version / TTL / checksum) at 22, TLVs from offset 26
 * (30 for 802.1Q-tagged frames). A CDP TLV header is 4 bytes: 2-byte BE type,
 * 2-byte BE length INCLUDING the 4-byte header itself.
 */
class CdpDecoderTest {

    private final CdpDecoder decoder = new CdpDecoder();

    private static final byte[] CDP_MULTICAST_DST =
        {0x01, 0x00, 0x0c, (byte) 0xcc, (byte) 0xcc, (byte) 0xcc};
    private static final byte[] SOURCE_MAC =
        {0x00, 0x1b, 0x54, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
    private static final String SOURCE_MAC_CANONICAL = "00:1b:54:ab:cd:ef";

    private static final int TLV_DEVICE_ID = 0x0001;
    private static final int TLV_ADDRESSES = 0x0002;
    private static final int TLV_PORT_ID = 0x0003;
    private static final int TLV_MGMT_ADDRESS = 0x0016;

    // ────────────────────────────────────────────────────────────────────────
    // In-test TLV / frame builders
    // ────────────────────────────────────────────────────────────────────────

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    private static byte[] be16(int v) {
        return new byte[]{(byte) (v >> 8), (byte) (v & 0xFF)};
    }

    private static byte[] be32(int v) {
        return new byte[]{(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) (v & 0xFF)};
    }

    /** CDP TLV: 2-byte BE type, 2-byte BE length INCLUDING this 4-byte header, then the value. */
    private static byte[] cdpTlv(int type, byte[] value) {
        return concat(be16(type), be16(value.length + 4), value);
    }

    /**
     * Address-block entry: protocolType (1 = NLPID, 2 = 802.2), protocolLength,
     * protocol bytes, 2-byte BE addressLength, address bytes.
     */
    private static byte[] addressEntry(int protocolType, byte[] protocol, byte[] address) {
        return concat(
            new byte[]{(byte) protocolType, (byte) protocol.length},
            protocol,
            be16(address.length),
            address);
    }

    /** Canonical IPv4 entry: NLPID (type 1), protocol 0xCC, 4-byte address. */
    private static byte[] ipv4Entry(int a, int b, int c, int d) {
        return addressEntry(1, new byte[]{(byte) 0xcc},
            new byte[]{(byte) a, (byte) b, (byte) c, (byte) d});
    }

    /** Addresses (0x0002) / Management-Address (0x0016) TLV: 4-byte BE count, then entries. */
    private static byte[] addressesTlv(int tlvType, int count, byte[]... entries) {
        return cdpTlv(tlvType, concat(be32(count), concat(entries)));
    }

    private static byte[] deviceIdTlv(String name) {
        return cdpTlv(TLV_DEVICE_ID, name.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] portIdTlv(String name) {
        return cdpTlv(TLV_PORT_ID, name.getBytes(StandardCharsets.UTF_8));
    }

    /** LLC {@code AA AA 03} + SNAP OUI {@code 00 00 0C} + 2-byte BE SNAP protocol ID. */
    private static byte[] snapHeader(int snapPid) {
        return concat(
            new byte[]{(byte) 0xaa, (byte) 0xaa, 0x03},   // LLC: DSAP, SSAP, ctrl
            new byte[]{0x00, 0x00, 0x0c},                  // SNAP OUI (Cisco)
            be16(snapPid));
    }

    /** 4-byte CDP header (version, TTL, checksum) followed by the TLV stream. */
    private static byte[] cdpBody(int version, int ttl, int checksum, byte[]... tlvs) {
        return concat(new byte[]{(byte) version, (byte) ttl}, be16(checksum), concat(tlvs));
    }

    /** Untagged 802.3 frame: dst + src + length (covers LLC through end of body) + payload. */
    private static byte[] snapFrame(int snapPid, byte[] body) {
        byte[] payload = concat(snapHeader(snapPid), body);
        return concat(CDP_MULTICAST_DST, SOURCE_MAC, be16(payload.length), payload);
    }

    /** Untagged CDP frame (SNAP protocol ID 0x2000). */
    private static byte[] cdpFrame(int version, int ttl, int checksum, byte[]... tlvs) {
        return snapFrame(0x2000, cdpBody(version, ttl, checksum, tlvs));
    }

    /** 802.1Q frame: TPID 0x8100 at 12-13, TCI at 14-15, 802.3 length at 16-17, LLC at 18. */
    private static byte[] vlanTaggedCdpFrame(int version, int ttl, int checksum, byte[]... tlvs) {
        byte[] payload = concat(snapHeader(0x2000), cdpBody(version, ttl, checksum, tlvs));
        return concat(CDP_MULTICAST_DST, SOURCE_MAC,
            new byte[]{(byte) 0x81, 0x00},   // TPID
            new byte[]{0x00, 0x64},          // TCI (VLAN 100)
            be16(payload.length),
            payload);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 1. Full frame — Device-ID + Addresses (one IPv4) + Port-ID
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_fullFrame_mapsAllFields() {
        byte[] f = cdpFrame(2, 180, 0x1a2b,
            deviceIdTlv("switch-cdp-01"),
            addressesTlv(TLV_ADDRESSES, 1, ipv4Entry(192, 168, 1, 20)),
            portIdTlv("GigabitEthernet0/1"));

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        DiscoveredNeighbor n = result.get(0);
        assertThat(n.ipAddress()).isEqualTo("192.168.1.20");
        assertThat(n.macAddress())
            .as("Ethernet src MAC must be lowercase colon-separated %%02x (ARP-reader format)")
            .isEqualTo(SOURCE_MAC_CANONICAL);
        assertThat(n.hostname()).isEqualTo("switch-cdp-01");
        assertThat(n.iface()).isEqualTo("eth0");
        assertThat(n.hwType()).isNull();
        assertThat(n.flags()).isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 2. No address TLV — MAC-only neighbor (ip null), hostname still set
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_noAddressTlv_ipNullMacAndHostnameSet() {
        byte[] f = cdpFrame(2, 180, 0x0000,
            deviceIdTlv("switch-cdp-01"),
            portIdTlv("GigabitEthernet0/2"));

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        DiscoveredNeighbor n = result.get(0);
        assertThat(n.ipAddress()).isNull();
        assertThat(n.macAddress()).isEqualTo(SOURCE_MAC_CANONICAL);
        assertThat(n.hostname()).isEqualTo("switch-cdp-01");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 3. Addresses TLV count=2: CLNS (NLPID 0x81) entry first, then IPv4 —
    //    the variable-length entry walk must skip the CLNS entry correctly
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_clnsEntryBeforeIpv4_ipv4StillFound() {
        byte[] clnsEntry = addressEntry(1, new byte[]{(byte) 0x81}, new byte[20]); // CLNS NSAP
        byte[] f = cdpFrame(2, 180, 0x0000,
            deviceIdTlv("multi-proto"),
            addressesTlv(TLV_ADDRESSES, 2, clnsEntry, ipv4Entry(10, 0, 0, 7)));

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).ipAddress())
            .as("the CLNS entry must be skipped by its self-describing size, not rejected")
            .isEqualTo("10.0.0.7");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 4. Two IPv4 entries — the first wins
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_twoIpv4Entries_firstWins() {
        byte[] f = cdpFrame(2, 180, 0x0000,
            deviceIdTlv("dual-ip"),
            addressesTlv(TLV_ADDRESSES, 2, ipv4Entry(10, 1, 1, 1), ipv4Entry(10, 2, 2, 2)));

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).ipAddress()).isEqualTo("10.1.1.1");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 5. Management-Address TLV 0x0016 only (no 0x0002) — same wire format,
    //    same address-block parser, ip decoded
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_mgmtAddressTlvOnly_ipDecoded() {
        byte[] f = cdpFrame(2, 180, 0x0000,
            deviceIdTlv("mgmt-only"),
            addressesTlv(TLV_MGMT_ADDRESS, 1, ipv4Entry(172, 16, 0, 9)));

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).ipAddress()).isEqualTo("172.16.0.9");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 6. IPv6-style 802.2 entry only (protocolType 2, protocol length 8) —
    //    skipped, ip null, MAC-only neighbor still yielded
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_ipv6StyleEntryOnly_skippedIpNull() {
        byte[] ipv6Protocol = {(byte) 0xaa, (byte) 0xaa, 0x03, 0x00, 0x00, 0x00, (byte) 0x86, (byte) 0xdd};
        byte[] ipv6Address = new byte[16];
        ipv6Address[0] = (byte) 0xfd;
        ipv6Address[15] = 0x01;
        byte[] f = cdpFrame(2, 180, 0x0000,
            deviceIdTlv("v6-only"),
            addressesTlv(TLV_ADDRESSES, 1, addressEntry(2, ipv6Protocol, ipv6Address)));

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).ipAddress())
            .as("IPv4-only by design — the 802.2 IPv6 entry is skipped, not decoded")
            .isNull();
        assertThat(result.get(0).macAddress()).isEqualTo(SOURCE_MAC_CANONICAL);
        assertThat(result.get(0).hostname()).isEqualTo("v6-only");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 7. Same multicast dst MAC but SNAP PID 0x2003 (VTP) — the mandatory
    //    SNAP-PID gate must yield an empty list (BPF dst-MAC filter over-capture)
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_vtpSnapPid_returnsEmpty() {
        byte[] vtp = snapFrame(0x2003, cdpBody(2, 180, 0x0000, deviceIdTlv("not-cdp")));

        assertThat(decoder.decode(vtp, "eth0"))
            .as("SNAP PID 0x2003 (VTP) shares the destination MAC but is not CDP")
            .isEmpty();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 8. Ethertype frame — field at 12-13 is 0x0800 (> 1500, not 0x8100): empty
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_ethertypeFrame_returnsEmpty() {
        byte[] ipv4Frame = concat(CDP_MULTICAST_DST, SOURCE_MAC,
            new byte[]{0x08, 0x00},                  // ethertype 0x0800 = IPv4, not an 802.3 length
            new byte[]{0x45, 0x00, 0x00, 0x14});     // arbitrary payload

        assertThat(decoder.decode(ipv4Frame, "eth0")).isEmpty();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 9. 802.1Q-tagged CDP frame — decodes identically to the untagged one
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_vlanTaggedFrame_decodesIdentically() {
        byte[] f = vlanTaggedCdpFrame(2, 180, 0x1a2b,
            deviceIdTlv("switch-cdp-01"),
            addressesTlv(TLV_ADDRESSES, 1, ipv4Entry(192, 168, 1, 20)),
            portIdTlv("GigabitEthernet0/1"));

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        DiscoveredNeighbor n = result.get(0);
        assertThat(n.ipAddress()).isEqualTo("192.168.1.20");
        assertThat(n.macAddress()).isEqualTo(SOURCE_MAC_CANONICAL);
        assertThat(n.hostname()).isEqualTo("switch-cdp-01");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 10. Truncated TLV — declared length overruns the parse bound: stop
    //     parsing, keep the fields collected so far, never throw
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_truncatedTlv_keepsFieldsCollectedSoFar() {
        // Device-ID TLV is intact; the following Addresses TLV declares length 200
        // but only one value byte follows.
        byte[] overrunning = {0x00, 0x02, 0x00, (byte) 200, 0x01};
        byte[] f = cdpFrame(2, 180, 0x0000, deviceIdTlv("switch-cdp-01"), overrunning);

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).hostname())
            .as("hostname collected before the overrunning TLV must be kept")
            .isEqualTo("switch-cdp-01");
        assertThat(result.get(0).ipAddress())
            .as("the truncated Addresses TLV must not contribute an IP")
            .isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 11. TLV length < 4 (smaller than its own header) — parsing stops, no
    //     infinite loop, fields collected so far are kept
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_tlvLengthBelowHeaderSize_stopsParsingKeepsFields() {
        // Declared TLV length 2 < the 4-byte header — a naive parser would spin
        // forever (zero advance) or go negative. A valid Addresses TLV sits AFTER
        // the malformed one; it must remain unreached, proving the parse stopped.
        byte[] badTlv = {0x00, 0x05, 0x00, 0x02};
        byte[] f = cdpFrame(2, 180, 0x0000,
            deviceIdTlv("stopper"),
            badTlv,
            addressesTlv(TLV_ADDRESSES, 1, ipv4Entry(10, 9, 8, 7)));

        List<DiscoveredNeighbor> result = assertTimeoutPreemptively(
            Duration.ofSeconds(5), () -> decoder.decode(f, "eth0"));

        assertThat(result).hasSize(1);
        assertThat(result.get(0).hostname()).isEqualTo("stopper");
        assertThat(result.get(0).ipAddress())
            .as("parsing must stop at the malformed TLV — later TLVs are unreachable")
            .isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 12. Wrong checksum — still decodes (checksum-ignored contract)
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_wrongChecksum_stillDecodes() {
        // 0xDEAD is not the valid ones'-complement checksum of this body. The decoder
        // must not validate it (Cisco's odd-length quirk falsely rejects real frames).
        byte[] f = cdpFrame(2, 180, 0xDEAD,
            deviceIdTlv("bad-checksum"),
            addressesTlv(TLV_ADDRESSES, 1, ipv4Entry(192, 168, 7, 7)));

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).hostname()).isEqualTo("bad-checksum");
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.7.7");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 13. CDP version byte 1 (CDPv1) — same TLV layout, decodes same as v2
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_cdpVersion1_decodesSameAsV2() {
        byte[] f = cdpFrame(1, 255, 0x0000,
            deviceIdTlv("v1-switch"),
            addressesTlv(TLV_ADDRESSES, 1, ipv4Entry(10, 0, 0, 3)));

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).hostname()).isEqualTo("v1-switch");
        assertThat(result.get(0).ipAddress()).isEqualTo("10.0.0.3");
        assertThat(result.get(0).macAddress()).isEqualTo(SOURCE_MAC_CANONICAL);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 14. 60-byte pad-extended frame — the 802.3 length field is the
    //     authoritative TLV parse bound; pad bytes are never parsed as TLVs
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_padExtendedFrame_lengthFieldBoundsTlvParsing() {
        // A minimal CDP frame is shorter than the 60-byte Ethernet minimum, so the
        // sender pad-extends it. Bytes beyond 14 + lengthField are pad, NOT TLVs —
        // even when they happen to look like a well-formed Addresses TLV.
        byte[] base = cdpFrame(2, 180, 0x0000, deviceIdTlv("padsw"));
        byte[] boobyTrappedPad = addressesTlv(TLV_ADDRESSES, 1, ipv4Entry(192, 0, 2, 99));
        byte[] f = concat(base, boobyTrappedPad);
        if (f.length < 60) {
            f = concat(f, new byte[60 - f.length]);
        }

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).hostname()).isEqualTo("padsw");
        assertThat(result.get(0).ipAddress())
            .as("bytes beyond the 802.3 length field are pad and must not be parsed as TLVs")
            .isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 15. Null / empty / sub-26-byte frame — empty list, never throw
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_nullEmptyOrTooShortFrame_returnsEmpty() {
        assertThat(decoder.decode(null, "eth0")).isEmpty();
        assertThat(decoder.decode(new byte[0], "eth0")).isEmpty();
        assertThat(decoder.decode(new byte[25], "eth0")).isEmpty();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 16. IPv4-shaped entry with addressLength != 4 — skipped safely, no throw
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_ipv4EntryWithWrongAddressLength_skippedSafely() {
        // protocolType 1 + protocol 0xCC but addressLength 6 — not a valid IPv4 entry.
        byte[] malformedIpv4 = addressEntry(1, new byte[]{(byte) 0xcc},
            new byte[]{10, 0, 0, 1, 0, 0});
        byte[] f = cdpFrame(2, 180, 0x0000,
            deviceIdTlv("odd-addr"),
            addressesTlv(TLV_ADDRESSES, 1, malformedIpv4));

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).ipAddress())
            .as("an IPv4-shaped entry with addressLength != 4 must be skipped, not decoded")
            .isNull();
        assertThat(result.get(0).macAddress()).isEqualTo(SOURCE_MAC_CANONICAL);
    }
}
