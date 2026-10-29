package io.castellum.discovery;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/**
 * Frame-level tests for the DHCP/BOOTP payload decoder.
 *
 * <p>Frames are assembled byte-by-byte with in-test builders: Ethernet header
 * (dst 6 / src 6 / ethertype 2, {@code 0x0800}; one 802.1Q tag shifts everything
 * by 4), IPv4 header at 14 (variable IHL — UDP starts at {@code 14 + IHL*4}),
 * UDP header (8 bytes, ports 67/68, the length field is the authoritative
 * payload bound), the 236-byte BOOTP fixed header, the magic cookie
 * {@code 63 82 53 63} at bootp+236, then the TLV option walk (1-byte code,
 * 1-byte len; pad 0 advances 1; end 255 stops). Key BOOTP offsets: op bootp+0,
 * htype +1, hlen +2, ciaddr +12, yiaddr +16, siaddr +20, giaddr +24,
 * chaddr +28 (16 bytes, first 6 = client MAC when htype==1 and hlen==6).
 * Minimum viable untagged frame: 14 + 20 + 8 + 240 = 282 bytes.
 */
class DhcpDecoderTest {

    private final DhcpDecoder decoder = new DhcpDecoder();

    private static final byte[] BROADCAST_DST =
        {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
    private static final byte[] SERVER_SRC_MAC =
        {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    private static final String SERVER_SRC_MAC_CANONICAL = "00:11:22:33:44:55";
    private static final byte[] CLIENT_CHADDR =
        {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
    private static final String CLIENT_MAC_CANONICAL = "52:54:00:12:34:56";
    private static final byte[] MAGIC_COOKIE = {0x63, (byte) 0x82, 0x53, 0x63};
    private static final byte[] ZERO_IP = {0, 0, 0, 0};

    // ────────────────────────────────────────────────────────────────────────
    // In-test frame builders — all offsets and codes are wire literals
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

    private static byte[] ip4(int a, int b, int c, int d) {
        return new byte[]{(byte) a, (byte) b, (byte) c, (byte) d};
    }

    /** Untagged Ethernet II frame: broadcast dst, src, ethertype 0x0800, payload. */
    private static byte[] ethFrame(byte[] srcMac, byte[] payload) {
        return concat(BROADCAST_DST, srcMac, new byte[]{0x08, 0x00}, payload);
    }

    /** 802.1Q frame: TPID 0x8100 at 12-13, TCI at 14-15, inner ethertype 0x0800 at 16-17. */
    private static byte[] vlanEthFrame(byte[] srcMac, byte[] payload) {
        return concat(BROADCAST_DST, srcMac,
            new byte[]{(byte) 0x81, 0x00},   // TPID
            new byte[]{0x00, 0x64},          // TCI (VLAN 100)
            new byte[]{0x08, 0x00},
            payload);
    }

    /**
     * IPv4 header of {@code ihl*4} bytes (IHL > 5 zero-fills the options area) +
     * payload. fragField is the raw flags/fragment-offset 16-bit value.
     */
    private static byte[] ipv4(int ihl, int proto, int fragField, byte[] payload) {
        int headerLen = ihl * 4;
        byte[] header = new byte[headerLen];
        header[0] = (byte) (0x40 | ihl);                 // version 4, IHL
        int total = headerLen + payload.length;
        header[2] = (byte) (total >> 8);
        header[3] = (byte) total;
        header[6] = (byte) (fragField >> 8);
        header[7] = (byte) fragField;
        header[8] = 64;                                   // TTL
        header[9] = (byte) proto;
        header[12] = (byte) 192; header[13] = (byte) 168; header[14] = 1; header[15] = 3;   // src IP
        header[16] = (byte) 255; header[17] = (byte) 255; header[18] = (byte) 255; header[19] = (byte) 255; // dst IP
        return concat(header, payload);
    }

    /** UDP header with the length field computed from the actual payload. */
    private static byte[] udp(int srcPort, int dstPort, byte[] payload) {
        return udpWithLen(srcPort, dstPort, 8 + payload.length, payload);
    }

    /** UDP header with an explicitly declared (possibly lying) length field. */
    private static byte[] udpWithLen(int srcPort, int dstPort, int declaredLen, byte[] payload) {
        return concat(be16(srcPort), be16(dstPort), be16(declaredLen), be16(0), payload);
    }

    /**
     * 236-byte BOOTP fixed header + cookie + options. chaddr is right-padded with
     * zeros to 16 bytes.
     */
    private static byte[] bootp(int op, int htype, int hlen,
                                byte[] ciaddr, byte[] yiaddr, byte[] siaddr, byte[] giaddr,
                                byte[] chaddr, byte[] cookie, byte[]... options) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(op);
        out.write(htype);
        out.write(hlen);
        out.write(0);                         // hops
        out.writeBytes(new byte[4]);          // xid
        out.writeBytes(new byte[4]);          // secs + flags
        out.writeBytes(ciaddr);               // bootp+12
        out.writeBytes(yiaddr);               // bootp+16
        out.writeBytes(siaddr);               // bootp+20
        out.writeBytes(giaddr);               // bootp+24
        byte[] ch = new byte[16];             // bootp+28
        System.arraycopy(chaddr, 0, ch, 0, Math.min(chaddr.length, 16));
        out.writeBytes(ch);
        out.writeBytes(new byte[64]);         // sname
        out.writeBytes(new byte[128]);        // file
        out.writeBytes(cookie);               // bootp+236
        for (byte[] o : options) {
            out.writeBytes(o);
        }
        return out.toByteArray();
    }

    /** TLV option: 1-byte code, 1-byte len from the value, value bytes. */
    private static byte[] opt(int code, byte[] value) {
        return concat(new byte[]{(byte) code, (byte) value.length}, value);
    }

    private static byte[] optString(int code, String value) {
        return opt(code, value.getBytes(StandardCharsets.UTF_8));
    }

    /** TLV option with a deliberately lying declared length. */
    private static byte[] optRaw(int code, int declaredLen, byte[] value) {
        return concat(new byte[]{(byte) code, (byte) declaredLen}, value);
    }

    private static final byte[] END = {(byte) 255};

    /** Standard untagged server→client reply frame (op given) with default plumbing. */
    private static byte[] replyFrame(byte[] yiaddr, byte[] giaddr, byte[]... options) {
        return ethFrame(SERVER_SRC_MAC, ipv4(5, 17, 0,
            udp(67, 68, bootp(2, 1, 6, ZERO_IP, yiaddr, ZERO_IP, giaddr,
                CLIENT_CHADDR, MAGIC_COOKIE, options))));
    }

    /** Standard untagged client→server request frame (op 1) with default plumbing. */
    private static byte[] requestFrame(byte[] ciaddr, byte[]... options) {
        return ethFrame(CLIENT_CHADDR, ipv4(5, 17, 0,
            udp(68, 67, bootp(1, 1, 6, ciaddr, ZERO_IP, ZERO_IP, ZERO_IP,
                CLIENT_CHADDR, MAGIC_COOKIE, options))));
    }

    private static DiscoveredNeighbor byIp(List<DiscoveredNeighbor> ns, String ip) {
        return ns.stream().filter(n -> ip.equals(n.ipAddress())).findFirst()
            .orElseThrow(() -> new AssertionError("no neighbor with ip " + ip + " in " + ns));
    }

    // ────────────────────────────────────────────────────────────────────────
    // 1. OFFER with distinct infra IPs — client + gateway + dns + server
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_offerDistinctInfraIps_yieldsFourNeighbors() {
        byte[] f = replyFrame(ip4(192, 168, 1, 50), ZERO_IP,
            opt(53, new byte[]{2}),                  // OFFER
            opt(3, ip4(192, 168, 1, 1)),
            opt(6, ip4(192, 168, 1, 2)),
            opt(54, ip4(192, 168, 1, 3)),
            END);

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(4);

        DiscoveredNeighbor client = byIp(result, "192.168.1.50");
        assertThat(client.macAddress())
            .as("client MAC from chaddr must be lowercase colon-separated")
            .isEqualTo(CLIENT_MAC_CANONICAL);
        assertThat(client.roleHint()).isNull();

        DiscoveredNeighbor gateway = byIp(result, "192.168.1.1");
        assertThat(gateway.roleHint()).isEqualTo(RoleHint.GATEWAY);
        assertThat(gateway.macAddress()).isNull();

        DiscoveredNeighbor dns = byIp(result, "192.168.1.2");
        assertThat(dns.roleHint()).isEqualTo(RoleHint.DNS_SERVER);
        assertThat(dns.macAddress()).isNull();

        DiscoveredNeighbor server = byIp(result, "192.168.1.3");
        assertThat(server.roleHint()).isEqualTo(RoleHint.DHCP_SERVER);
        assertThat(server.macAddress())
            .as("non-relayed reply: server neighbor carries the Ethernet src MAC")
            .isEqualTo(SERVER_SRC_MAC_CANONICAL);

        assertThat(result).allSatisfy(n -> assertThat(n.iface()).isEqualTo("eth0"));
    }

    // ────────────────────────────────────────────────────────────────────────
    // 2. ACK home-router collapse: opt3 = opt6 = opt54 → ONE infra neighbor
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_ackHomeRouterCollapse_yieldsClientPlusSingleInfraNeighbor() {
        byte[] f = replyFrame(ip4(192, 168, 1, 50), ZERO_IP,
            opt(53, new byte[]{5}),                  // ACK
            opt(3, ip4(192, 168, 1, 1)),
            opt(6, ip4(192, 168, 1, 1)),
            opt(54, ip4(192, 168, 1, 1)),
            END);

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result)
            .as("same-IP infra rows must dedupe in-frame to one neighbor")
            .hasSize(2);

        DiscoveredNeighbor infra = byIp(result, "192.168.1.1");
        assertThat(infra.roleHint())
            .as("rank merge: GATEWAY (5) beats DHCP_SERVER (4) and DNS_SERVER (3)")
            .isEqualTo(RoleHint.GATEWAY);
        assertThat(infra.macAddress())
            .as("the collapsed infra neighbor keeps the server's src MAC")
            .isEqualTo(SERVER_SRC_MAC_CANONICAL);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 3. DISCOVER: chaddr + opt12 hostname; opt50 requested-IP never used as ip
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_discover_macAndHostnameOnly_requestedIpIgnored() {
        byte[] f = requestFrame(ZERO_IP,
            opt(53, new byte[]{1}),                  // DISCOVER
            optString(12, "laptop-7"),
            opt(50, ip4(10, 0, 0, 99)),
            END);

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        DiscoveredNeighbor n = result.get(0);
        assertThat(n.ipAddress())
            .as("option 50 is an unconfirmed claim and must NOT become ipAddress")
            .isNull();
        assertThat(n.macAddress()).isEqualTo(CLIENT_MAC_CANONICAL);
        assertThat(n.hostname()).isEqualTo("laptop-7");
        assertThat(n.roleHint()).isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 4. RENEW REQUEST: ciaddr is the client's own IP; opt54 in a REQUEST never
    //    mints a server neighbor (reply-only hint rule)
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_renewRequestWithCiaddr_clientNeighborOnly_noServerNeighbor() {
        byte[] f = requestFrame(ip4(192, 168, 1, 50),
            opt(53, new byte[]{3}),                  // REQUEST
            opt(54, ip4(192, 168, 1, 3)),
            END);

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result)
            .as("BOOTREQUEST yields at most the client — no infra hints from requests")
            .hasSize(1);
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.1.50");
        assertThat(result.get(0).macAddress()).isEqualTo(CLIENT_MAC_CANONICAL);
        assertThat(result.get(0).roleHint()).isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 5. NAK: yiaddr zero, valid chaddr → MAC-only client neighbor
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_nakZeroYiaddr_yieldsMacOnlyClient() {
        byte[] f = replyFrame(ZERO_IP, ZERO_IP,
            opt(53, new byte[]{6}),                  // NAK
            END);

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).ipAddress()).isNull();
        assertThat(result.get(0).macAddress()).isEqualTo(CLIENT_MAC_CANONICAL);
        assertThat(result.get(0).roleHint()).isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 6. hlen=16 (htype=1): chaddr unusable — DISCOVER empties, OFFER keeps ip
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_hlen16_chaddrSuppressed() {
        byte[] discover = ethFrame(CLIENT_CHADDR, ipv4(5, 17, 0,
            udp(68, 67, bootp(1, 1, 16, ZERO_IP, ZERO_IP, ZERO_IP, ZERO_IP,
                CLIENT_CHADDR, MAGIC_COOKIE, opt(53, new byte[]{1}), END))));
        assertThat(decoder.decode(discover, "eth0"))
            .as("no MAC and no IP — nothing keyable to emit")
            .isEmpty();

        byte[] offer = ethFrame(SERVER_SRC_MAC, ipv4(5, 17, 0,
            udp(67, 68, bootp(2, 1, 16, ZERO_IP, ip4(192, 168, 1, 50), ZERO_IP, ZERO_IP,
                CLIENT_CHADDR, MAGIC_COOKIE, opt(53, new byte[]{2}), END))));
        List<DiscoveredNeighbor> result = decoder.decode(offer, "eth0");
        assertThat(result).hasSize(1);
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.1.50");
        assertThat(result.get(0).macAddress())
            .as("hlen != 6 — chaddr must not be formatted as a MAC")
            .isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 7. htype=6 (IEEE 802, non-Ethernet) — same chaddr suppression
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_htype6_chaddrSuppressed() {
        byte[] discover = ethFrame(CLIENT_CHADDR, ipv4(5, 17, 0,
            udp(68, 67, bootp(1, 6, 6, ZERO_IP, ZERO_IP, ZERO_IP, ZERO_IP,
                CLIENT_CHADDR, MAGIC_COOKIE, opt(53, new byte[]{1}), END))));
        assertThat(decoder.decode(discover, "eth0")).isEmpty();

        byte[] offer = ethFrame(SERVER_SRC_MAC, ipv4(5, 17, 0,
            udp(67, 68, bootp(2, 6, 6, ZERO_IP, ip4(192, 168, 1, 50), ZERO_IP, ZERO_IP,
                CLIENT_CHADDR, MAGIC_COOKIE, opt(53, new byte[]{2}), END))));
        List<DiscoveredNeighbor> result = decoder.decode(offer, "eth0");
        assertThat(result).hasSize(1);
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.1.50");
        assertThat(result.get(0).macAddress())
            .as("htype != 1 — chaddr must not be formatted as a MAC")
            .isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 8. Missing / wrong magic cookie → empty (pure BOOTP out of scope)
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_missingOrWrongMagicCookie_returnsEmpty() {
        byte[] wrongCookie = ethFrame(SERVER_SRC_MAC, ipv4(5, 17, 0,
            udp(67, 68, bootp(2, 1, 6, ZERO_IP, ip4(192, 168, 1, 50), ZERO_IP, ZERO_IP,
                CLIENT_CHADDR, new byte[]{0x63, (byte) 0x82, 0x53, 0x64},
                opt(53, new byte[]{2}), END))));
        assertThat(decoder.decode(wrongCookie, "eth0"))
            .as("wrong cookie byte — not DHCP")
            .isEmpty();

        // Frame ends exactly at bootp+236 — no cookie bytes at all.
        byte[] noCookie = ethFrame(SERVER_SRC_MAC, ipv4(5, 17, 0,
            udp(67, 68, bootp(2, 1, 6, ZERO_IP, ip4(192, 168, 1, 50), ZERO_IP, ZERO_IP,
                CLIENT_CHADDR, new byte[0]))));
        assertThat(decoder.decode(noCookie, "eth0"))
            .as("cookie absent — structurally short of a DHCP unit")
            .isEmpty();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 9. Option declared len overruns the payload — keep options collected
    //    before the overrun, stop the walk, never throw
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_optionLenOverrun_keepsOptionsCollectedBeforeOverrun() {
        byte[] f = replyFrame(ip4(192, 168, 1, 50), ZERO_IP,
            opt(3, ip4(192, 168, 1, 1)),
            optRaw(12, 200, new byte[]{0x61, 0x62}));   // declares 200, 2 bytes follow

        List<DiscoveredNeighbor> result = assertTimeoutPreemptively(
            Duration.ofSeconds(5), () -> decoder.decode(f, "eth0"));

        DiscoveredNeighbor gateway = byIp(result, "192.168.1.1");
        assertThat(gateway.roleHint())
            .as("option 3 parsed before the overrunning option must be kept")
            .isEqualTo(RoleHint.GATEWAY);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 10. Pads before, end before garbage: 0,0,opt3,255,<garbage> — the
    //     garbage (a well-formed-looking opt6) must never be parsed
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_padsAndEndOption_bytesAfterEndNeverParsed() {
        byte[] f = replyFrame(ip4(192, 168, 1, 50), ZERO_IP,
            new byte[]{0, 0},                        // two pad options
            opt(3, ip4(192, 168, 1, 1)),
            END,
            opt(6, ip4(8, 8, 8, 8)));                // garbage after end

        List<DiscoveredNeighbor> result = assertTimeoutPreemptively(
            Duration.ofSeconds(5), () -> decoder.decode(f, "eth0"));

        assertThat(byIp(result, "192.168.1.1").roleHint()).isEqualTo(RoleHint.GATEWAY);
        assertThat(result)
            .as("bytes after option 255 are never parsed — no DNS neighbor")
            .noneSatisfy(n -> assertThat(n.ipAddress()).isEqualTo("8.8.8.8"));
    }

    // ────────────────────────────────────────────────────────────────────────
    // 11. opt3 len=2 (< 4) — no gateway hint, the walk continues to a valid opt6
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_opt3TooShort_skippedButWalkContinues() {
        byte[] f = replyFrame(ip4(192, 168, 1, 50), ZERO_IP,
            opt(3, new byte[]{1, 2}),                // len 2 — unusable
            opt(6, ip4(192, 168, 1, 2)),
            END);

        List<DiscoveredNeighbor> result = assertTimeoutPreemptively(
            Duration.ofSeconds(5), () -> decoder.decode(f, "eth0"));

        assertThat(result)
            .as("a too-short option 3 must not mint a gateway hint")
            .noneSatisfy(n -> assertThat(n.roleHint()).isEqualTo(RoleHint.GATEWAY));
        assertThat(byIp(result, "192.168.1.2").roleHint())
            .as("the walk must continue past the short option (len still honored)")
            .isEqualTo(RoleHint.DNS_SERVER);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 12. opt3=0.0.0.0 / opt6=255.255.255.255 — both skipped
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_zeroAndBroadcastOptionValues_neverBecomeNeighbors() {
        byte[] f = replyFrame(ip4(192, 168, 1, 50), ZERO_IP,
            opt(3, ip4(0, 0, 0, 0)),
            opt(6, ip4(255, 255, 255, 255)),
            END);

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result)
            .as("0.0.0.0 and 255.255.255.255 option values yield nothing — only the client remains")
            .hasSize(1);
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.1.50");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 13. IHL=6 (IPv4 options present) — all offsets shift by 4 correctly
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_ihl6_decodesIdentically() {
        byte[] f = ethFrame(SERVER_SRC_MAC, ipv4(6, 17, 0,
            udp(67, 68, bootp(2, 1, 6, ZERO_IP, ip4(192, 168, 1, 50), ZERO_IP, ZERO_IP,
                CLIENT_CHADDR, MAGIC_COOKIE,
                opt(53, new byte[]{2}),
                opt(3, ip4(192, 168, 1, 1)),
                END))));

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(2);
        assertThat(byIp(result, "192.168.1.50").macAddress()).isEqualTo(CLIENT_MAC_CANONICAL);
        assertThat(byIp(result, "192.168.1.1").roleHint()).isEqualTo(RoleHint.GATEWAY);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 14. 802.1Q-tagged frame — decodes identically to the untagged one
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_vlanTaggedFrame_decodesIdentically() {
        byte[] f = vlanEthFrame(SERVER_SRC_MAC, ipv4(5, 17, 0,
            udp(67, 68, bootp(2, 1, 6, ZERO_IP, ip4(192, 168, 1, 50), ZERO_IP, ZERO_IP,
                CLIENT_CHADDR, MAGIC_COOKIE,
                opt(53, new byte[]{2}),
                opt(3, ip4(192, 168, 1, 1)),
                END))));

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(2);
        assertThat(byIp(result, "192.168.1.50").macAddress()).isEqualTo(CLIENT_MAC_CANONICAL);
        assertThat(byIp(result, "192.168.1.1").roleHint()).isEqualTo(RoleHint.GATEWAY);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 15. Non-UDP protocol / non-67-68 ports — empty
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_nonUdpProtocolOrWrongPorts_returnsEmpty() {
        byte[] bootpBody = bootp(2, 1, 6, ZERO_IP, ip4(192, 168, 1, 50), ZERO_IP, ZERO_IP,
            CLIENT_CHADDR, MAGIC_COOKIE, opt(53, new byte[]{2}), END);

        byte[] tcp = ethFrame(SERVER_SRC_MAC, ipv4(5, 6, 0, udp(67, 68, bootpBody)));
        assertThat(decoder.decode(tcp, "eth0"))
            .as("IPv4 protocol 6 (TCP) is not DHCP transport")
            .isEmpty();

        byte[] dnsPorts = ethFrame(SERVER_SRC_MAC, ipv4(5, 17, 0, udp(53, 53, bootpBody)));
        assertThat(decoder.decode(dnsPorts, "eth0"))
            .as("neither port in {67, 68} — the port gate must reject")
            .isEmpty();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 16. IPv4 fragments — empty (no reassembly)
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_fragments_returnEmpty() {
        byte[] bootpBody = bootp(2, 1, 6, ZERO_IP, ip4(192, 168, 1, 50), ZERO_IP, ZERO_IP,
            CLIENT_CHADDR, MAGIC_COOKIE, opt(53, new byte[]{2}), END);

        byte[] laterFragment = ethFrame(SERVER_SRC_MAC, ipv4(5, 17, 185, udp(67, 68, bootpBody)));
        assertThat(decoder.decode(laterFragment, "eth0"))
            .as("fragment offset != 0 cannot carry a parseable UDP+BOOTP unit")
            .isEmpty();

        byte[] firstFragmentMf = ethFrame(SERVER_SRC_MAC, ipv4(5, 17, 0x2000, udp(67, 68, bootpBody)));
        assertThat(decoder.decode(firstFragmentMf, "eth0"))
            .as("MF bit set — incomplete datagram, skip")
            .isEmpty();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 17. Frame truncated mid-chaddr (< 282 bytes) — empty, never throw
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_truncatedMidChaddr_returnsEmpty() {
        byte[] full = replyFrame(ip4(192, 168, 1, 50), ZERO_IP, opt(53, new byte[]{2}), END);
        byte[] truncated = Arrays.copyOf(full, 14 + 20 + 8 + 32);  // cut inside chaddr (bootp+28..43)

        assertThat(decoder.decode(truncated, "eth0")).isEmpty();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 18. UDP length field is the authoritative bound — an option beyond
    //     udpStart+udpLen is trailing pad and never parsed
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_udpLengthBoundsOptionWalk_optionBeyondDeclaredLenNeverParsed() {
        byte[] inBound = concat(opt(3, ip4(192, 168, 1, 1)));   // 6 bytes
        byte[] beyond = concat(opt(6, ip4(192, 168, 1, 2)), END);
        byte[] body = bootp(2, 1, 6, ZERO_IP, ip4(192, 168, 1, 50), ZERO_IP, ZERO_IP,
            CLIENT_CHADDR, MAGIC_COOKIE, inBound, beyond);
        // Declared UDP length covers the fixed header + cookie + opt3 only.
        int declaredLen = 8 + 236 + 4 + inBound.length;
        byte[] f = ethFrame(SERVER_SRC_MAC, ipv4(5, 17, 0, udpWithLen(67, 68, declaredLen, body)));

        List<DiscoveredNeighbor> result = assertTimeoutPreemptively(
            Duration.ofSeconds(5), () -> decoder.decode(f, "eth0"));

        assertThat(byIp(result, "192.168.1.1").roleHint()).isEqualTo(RoleHint.GATEWAY);
        assertThat(result)
            .as("the opt6 after udpStart+udpLen is Ethernet pad territory — never parsed")
            .noneSatisfy(n -> assertThat(n.ipAddress()).isEqualTo("192.168.1.2"));
    }

    // ────────────────────────────────────────────────────────────────────────
    // 19. Blank option-12 hostname → null
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_blankHostnameOption_hostnameNull() {
        byte[] f = requestFrame(ZERO_IP,
            opt(53, new byte[]{1}),
            optString(12, "   "),
            END);

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).hostname())
            .as("a blank hostname option trims to null")
            .isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 20. Duplicate option 3 — first occurrence wins
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_duplicateOpt3_firstOccurrenceWins() {
        byte[] f = replyFrame(ip4(192, 168, 1, 50), ZERO_IP,
            opt(3, ip4(192, 168, 1, 1)),
            opt(3, ip4(192, 168, 1, 99)),
            END);

        List<DiscoveredNeighbor> result = assertTimeoutPreemptively(
            Duration.ofSeconds(5), () -> decoder.decode(f, "eth0"));

        assertThat(byIp(result, "192.168.1.1").roleHint()).isEqualTo(RoleHint.GATEWAY);
        assertThat(result)
            .as("first-occurrence-wins: the second option 3 must be ignored")
            .noneSatisfy(n -> assertThat(n.ipAddress()).isEqualTo("192.168.1.99"));
    }

    // ────────────────────────────────────────────────────────────────────────
    // 21. Relayed ACK (giaddr != 0) — server neighbor's MAC must be null
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_relayedAck_serverNeighborMacNull() {
        byte[] f = replyFrame(ip4(192, 168, 1, 50), ip4(10, 9, 9, 9),
            opt(53, new byte[]{5}),
            opt(54, ip4(192, 168, 1, 3)),
            END);

        List<DiscoveredNeighbor> result = decoder.decode(f, "eth0");

        DiscoveredNeighbor server = byIp(result, "192.168.1.3");
        assertThat(server.roleHint()).isEqualTo(RoleHint.DHCP_SERVER);
        assertThat(server.macAddress())
            .as("a relayed reply's src MAC belongs to the relay, not the DHCP server")
            .isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 22. Null / empty / 41-byte frame — empty list, never throw
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_nullEmptyOrShortFrame_returnsEmpty() {
        assertThat(decoder.decode(null, "eth0")).isEmpty();
        assertThat(decoder.decode(new byte[0], "eth0")).isEmpty();
        assertThat(decoder.decode(new byte[41], "eth0")).isEmpty();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 23. Unknown op (3) — empty list
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_unknownOp_returnsEmpty() {
        byte[] f = ethFrame(SERVER_SRC_MAC, ipv4(5, 17, 0,
            udp(67, 68, bootp(3, 1, 6, ZERO_IP, ip4(192, 168, 1, 50), ZERO_IP, ZERO_IP,
                CLIENT_CHADDR, MAGIC_COOKIE, opt(53, new byte[]{2}), END))));

        assertThat(decoder.decode(f, "eth0"))
            .as("op values other than 1/2 are not BOOTP traffic we understand")
            .isEmpty();
    }
}
