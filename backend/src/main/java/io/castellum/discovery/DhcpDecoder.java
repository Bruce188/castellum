package io.castellum.discovery;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Frame-level DHCP/BOOTP payload decoder.
 *
 * <p>Parses a full Ethernet + IPv4 + UDP + BOOTP frame and yields neighbors carrying
 * {@link RoleHint} evidence: the client (chaddr/yiaddr/ciaddr/option 12), and — for
 * BOOTREPLY frames — gateway (option 3), DNS (option 6) and DHCP-server (option 54)
 * hint neighbors. Never throws on malformed input (empty-list / stop-keep-collected
 * tolerance contract, mirroring {@link LldpDecoder}/{@link CdpDecoder}).
 *
 * <p>Structure gates, in order: EtherType {@code 0x0800} (one optional 802.1Q tag via
 * {@link EtherFraming}), IPv4 version 4 with IHL-derived header length, no fragments,
 * protocol 17, at least one UDP port in {67, 68}, the UDP length field as the
 * authoritative payload bound, the 236-byte BOOTP fixed header plus the 4-byte magic
 * cookie {@code 63 82 53 63}, op 1 (BOOTREQUEST) or 2 (BOOTREPLY). The option walk is
 * first-occurrence-wins; a declared option length overrunning the bound stops the walk
 * keeping the options collected so far.
 *
 * <p>BOOTREQUEST yields at most the client neighbor (ciaddr when nonzero, chaddr as MAC
 * only when {@code htype == 1 && hlen == 6}, option-12 hostname) — options in requests
 * are unconfirmed claims and never mint infra hints. BOOTREPLY additionally yields
 * hint neighbors for usable (non-zero, non-broadcast) option 3/6/54 values, deduped
 * in-frame by IP with rank-max hint merge; the option-54 server carries the Ethernet
 * source MAC only when {@code giaddr == 0} (a relayed reply's src MAC belongs to the
 * relay, not the server).
 */
@Service
public class DhcpDecoder {

    private static final int IPPROTO_UDP = 17;
    private static final int ETHERTYPE_IPV4 = 0x0800;
    private static final int BOOTREQUEST = 1;
    private static final int BOOTREPLY = 2;

    private static final int OPT_PAD = 0;
    private static final int OPT_ROUTER = 3;
    private static final int OPT_DNS = 6;
    private static final int OPT_HOSTNAME = 12;
    private static final int OPT_SERVER_ID = 54;
    private static final int OPT_END = 255;

    /**
     * Decodes one captured frame. Fits
     * {@code CaptureLoop.captureAndDecode}'s {@code BiFunction<byte[],String,List<DiscoveredNeighbor>>}.
     *
     * @param frame raw Ethernet frame bytes (may be null/short/garbage — never throws)
     * @param iface capture interface label, propagated onto every neighbor
     * @return decoded neighbors; empty when the frame is not a parseable DHCP unit
     */
    public List<DiscoveredNeighbor> decode(byte[] frame, String iface) {
        if (frame == null || frame.length < 14) {
            return List.of();
        }
        EtherFraming framing = EtherFraming.of(frame);
        if (framing == null || framing.typeOrLength() != ETHERTYPE_IPV4) {
            return List.of();
        }
        int ipStart = framing.payloadStart();
        if (ipStart + 20 > frame.length) {
            return List.of();
        }
        int versionIhl = frame[ipStart] & 0xFF;
        if ((versionIhl >> 4) != 4) {
            return List.of();
        }
        int ipHeaderLen = (versionIhl & 0x0F) * 4;
        if (ipHeaderLen < 20 || ipStart + ipHeaderLen > frame.length) {
            return List.of();
        }
        int fragField = readU16(frame, ipStart + 6);
        if ((fragField & 0x1FFF) != 0 || (fragField & 0x2000) != 0) {
            return List.of(); // fragment — no reassembly
        }
        if ((frame[ipStart + 9] & 0xFF) != IPPROTO_UDP) {
            return List.of();
        }
        int udpStart = ipStart + ipHeaderLen;
        if (udpStart + 8 > frame.length) {
            return List.of();
        }
        int srcPort = readU16(frame, udpStart);
        int dstPort = readU16(frame, udpStart + 2);
        if (!isDhcpPort(srcPort) && !isDhcpPort(dstPort)) {
            return List.of();
        }
        // The UDP length field is the authoritative payload bound — Ethernet pad bytes
        // beyond it are never parsed as options.
        int udpLen = readU16(frame, udpStart + 4);
        int bootpEnd = Math.min(frame.length, udpStart + udpLen);
        int bootp = udpStart + 8;
        if (bootp + 240 > bootpEnd) {
            return List.of(); // structurally short of fixed header + cookie
        }
        if ((frame[bootp + 236] & 0xFF) != 0x63 || (frame[bootp + 237] & 0xFF) != 0x82
                || (frame[bootp + 238] & 0xFF) != 0x53 || (frame[bootp + 239] & 0xFF) != 0x63) {
            return List.of(); // wrong magic cookie — pure BOOTP out of scope
        }
        int op = frame[bootp] & 0xFF;
        if (op != BOOTREQUEST && op != BOOTREPLY) {
            return List.of();
        }
        int htype = frame[bootp + 1] & 0xFF;
        int hlen = frame[bootp + 2] & 0xFF;
        String clientMac = (htype == 1 && hlen == 6) ? MacFormat.format(frame, bootp + 28) : null;

        Map<Integer, byte[]> options = walkOptions(frame, bootp + 240, bootpEnd);
        String hostname = hostnameOf(options.get(OPT_HOSTNAME));

        if (op == BOOTREQUEST) {
            String clientIp = nonZeroIp(frame, bootp + 12); // ciaddr
            if (clientIp == null && clientMac == null) {
                return List.of(); // nothing keyable to emit
            }
            return List.of(new DiscoveredNeighbor(clientIp, clientMac, null, null, iface, hostname, null));
        }

        // BOOTREPLY — client (yiaddr) plus infra hint neighbors, deduped by IP in-frame.
        List<DiscoveredNeighbor> result = new ArrayList<>();
        Map<String, DiscoveredNeighbor> byIp = new LinkedHashMap<>();
        String clientIp = nonZeroIp(frame, bootp + 16); // yiaddr
        if (clientIp != null) {
            byIp.put(clientIp, new DiscoveredNeighbor(clientIp, clientMac, null, null, iface, hostname, null));
        } else if (clientMac != null) {
            // NAK: yiaddr zero — a MAC-only client neighbor (no IP key to merge on).
            result.add(new DiscoveredNeighbor(null, clientMac, null, null, iface, hostname, null));
        }
        String gatewayIp = optionIp(options.get(OPT_ROUTER));
        if (gatewayIp != null) {
            byIp.merge(gatewayIp,
                new DiscoveredNeighbor(gatewayIp, null, null, null, iface, null, RoleHint.GATEWAY),
                DhcpDecoder::mergeNeighbor);
        }
        String dnsIp = optionIp(options.get(OPT_DNS));
        if (dnsIp != null) {
            byIp.merge(dnsIp,
                new DiscoveredNeighbor(dnsIp, null, null, null, iface, null, RoleHint.DNS_SERVER),
                DhcpDecoder::mergeNeighbor);
        }
        String serverIp = optionIp(options.get(OPT_SERVER_ID));
        if (serverIp != null) {
            // giaddr != 0 means the frame was relayed: the Ethernet src MAC belongs to
            // the relay agent, not the DHCP server.
            boolean relayed = nonZeroIp(frame, bootp + 24) != null;
            String serverMac = relayed ? null : MacFormat.format(frame, 6);
            byIp.merge(serverIp,
                new DiscoveredNeighbor(serverIp, serverMac, null, null, iface, null, RoleHint.DHCP_SERVER),
                DhcpDecoder::mergeNeighbor);
        }
        result.addAll(byIp.values());
        return result;
    }

    /**
     * First-occurrence-wins TLV walk: pad (0) advances one byte, end (255) stops, a
     * declared length overrunning the bound stops the walk keeping options collected
     * so far. Never throws.
     */
    private static Map<Integer, byte[]> walkOptions(byte[] frame, int start, int end) {
        Map<Integer, byte[]> options = new HashMap<>();
        int pos = start;
        while (pos < end) {
            int code = frame[pos] & 0xFF;
            if (code == OPT_PAD) {
                pos++;
                continue;
            }
            if (code == OPT_END) {
                break;
            }
            if (pos + 2 > end) {
                break; // code without a length byte — truncated
            }
            int len = frame[pos + 1] & 0xFF;
            if (pos + 2 + len > end) {
                break; // declared length overruns the bound — keep collected options
            }
            options.putIfAbsent(code, Arrays.copyOfRange(frame, pos + 2, pos + 2 + len));
            pos += 2 + len;
        }
        return options;
    }

    /** In-frame same-IP merge: rank-max hint, MAC and hostname fill-when-null. */
    private static DiscoveredNeighbor mergeNeighbor(DiscoveredNeighbor a, DiscoveredNeighbor b) {
        return new DiscoveredNeighbor(
            a.ipAddress(),
            a.macAddress() != null ? a.macAddress() : b.macAddress(),
            null, null,
            a.iface(),
            a.hostname() != null ? a.hostname() : b.hostname(),
            RoleHint.rank(b.roleHint()) > RoleHint.rank(a.roleHint()) ? b.roleHint() : a.roleHint());
    }

    /** Option-12 hostname: trimmed, blank → null. */
    private static String hostnameOf(byte[] value) {
        if (value == null) {
            return null;
        }
        String name = new String(value, StandardCharsets.UTF_8).trim();
        return name.isEmpty() ? null : name;
    }

    /** 4-byte fixed-header address at {@code offset}: literal when nonzero, else null. */
    private static String nonZeroIp(byte[] frame, int offset) {
        if (frame[offset] == 0 && frame[offset + 1] == 0
                && frame[offset + 2] == 0 && frame[offset + 3] == 0) {
            return null;
        }
        return WireAddress.toLiteral(Arrays.copyOfRange(frame, offset, offset + 4));
    }

    /**
     * Usable option-carried IP: at least 4 value bytes (first 4 win), neither
     * {@code 0.0.0.0} nor {@code 255.255.255.255}. Anything else yields null —
     * the option is skipped, never the frame.
     */
    private static String optionIp(byte[] value) {
        if (value == null || value.length < 4) {
            return null;
        }
        boolean allZero = true;
        boolean allOnes = true;
        for (int i = 0; i < 4; i++) {
            if (value[i] != 0) {
                allZero = false;
            }
            if ((value[i] & 0xFF) != 0xFF) {
                allOnes = false;
            }
        }
        if (allZero || allOnes) {
            return null;
        }
        return WireAddress.toLiteral(Arrays.copyOf(value, 4));
    }

    private static boolean isDhcpPort(int port) {
        return port == 67 || port == 68;
    }

    private static int readU16(byte[] buf, int offset) {
        return ((buf[offset] & 0xFF) << 8) | (buf[offset + 1] & 0xFF);
    }
}
