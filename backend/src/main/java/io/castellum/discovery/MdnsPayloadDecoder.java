package io.castellum.discovery;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Bounded, never-throw DNS message parser over one raw mDNS datagram payload.
 *
 * <p>Hears records JmDNS never surfaces — A records and Apple {@code _device-info} TXT
 * answers flying between third parties — and yields one neighbor per A record, with a
 * chassis {@link RoleHint} ({@code model=MacBook*} → LAPTOP_CHASSIS; iMac, Macmini
 * and MacPro prefixes → DESKTOP_CHASSIS) attached when the matching
 * {@code _device-info} TXT owner shares the A record's host label (case-insensitive).
 *
 * <p>Tolerance contract: the QR bit must be 1 (queries are never evidence of an
 * answering host); the section counts are bounds-checked claims, never trusted; a
 * structural overrun (truncated record header, lying RDLENGTH, malformed name) stops
 * the datagram keeping neighbors collected so far; a name-VALUE violation (forward or
 * self compression pointer, jump or length bomb) discards only that record's name —
 * the structural walk continues. AAAA records are skipped (IPv4-only for now).
 *
 * <p>Name decompression is DoS-bounded: compression pointers must target an offset
 * strictly before the pointer itself (backward-only), at most 16 pointer jumps per
 * name, assembled names capped at 255 bytes. The structural name skip never follows
 * pointers at all — a pointer is two bytes in place.
 */
@Service
public class MdnsPayloadDecoder {

    private static final int TYPE_A = 1;
    private static final int TYPE_TXT = 16;
    private static final int QR_MASK = 0x8000;
    private static final int MAX_POINTER_JUMPS = 16;
    private static final int MAX_NAME_BYTES = 255;
    private static final String DEVICE_INFO_SUFFIX = "._device-info._tcp.local.";

    /**
     * Decodes one mDNS datagram payload (UDP body — no IP/UDP headers).
     *
     * @param payload raw DNS message bytes (may be null/short/garbage — never throws)
     * @return decoded neighbors; empty for queries and unparseable datagrams
     */
    public List<DiscoveredNeighbor> decode(byte[] payload) {
        if (payload == null || payload.length < 12) {
            return List.of();
        }
        int flags = readU16(payload, 2);
        if ((flags & QR_MASK) == 0) {
            return List.of(); // QR=0 — a query, never evidence of an answering host
        }
        int qdCount = readU16(payload, 4);
        int recordCount = readU16(payload, 6) + readU16(payload, 8) + readU16(payload, 10);

        int pos = 12;
        for (int q = 0; q < qdCount; q++) {
            int afterName = skipName(payload, pos);
            if (afterName < 0 || afterName + 4 > payload.length) {
                return List.of(); // malformed question section — nothing collected yet
            }
            pos = afterName + 4; // QTYPE + QCLASS
        }

        // Collect over the whole datagram first (TXT may precede or follow its A record),
        // then assemble: the hint attaches by shared first label.
        List<String[]> aPairs = new ArrayList<>();          // {ownerName, ipLiteral}
        Map<String, RoleHint> hintByLabel = new HashMap<>();

        for (int r = 0; r < recordCount; r++) {
            if (pos >= payload.length) {
                break; // counts are claims — the datagram end is authoritative
            }
            String name = readNameValue(payload, pos); // null on pointer violation — record skipped, walk continues
            int afterName = skipName(payload, pos);
            if (afterName < 0) {
                break; // structural overrun — stop, keep collected
            }
            pos = afterName;
            if (pos + 10 > payload.length) {
                break; // truncated record header
            }
            int type = readU16(payload, pos);
            // CLASS at pos+2 is not gated: the mDNS cache-flush bit rides 0x8000 and
            // both 0x0001 and 0x8001 must parse identically.
            int rdlength = readU16(payload, pos + 8);
            pos += 10;
            if (pos + rdlength > payload.length) {
                break; // lying RDLENGTH — stop, keep collected
            }
            if (name != null && type == TYPE_A && rdlength == 4) {
                String ip = WireAddress.toLiteral(Arrays.copyOfRange(payload, pos, pos + 4));
                aPairs.add(new String[]{name, ip});
            } else if (name != null && type == TYPE_TXT
                    && name.toLowerCase(Locale.ROOT).endsWith(DEVICE_INFO_SUFFIX)) {
                RoleHint hint = mapModelToHint(findModelValue(payload, pos, rdlength));
                if (hint != null) {
                    hintByLabel.putIfAbsent(firstLabel(name), hint);
                }
            }
            pos += rdlength;
        }

        List<DiscoveredNeighbor> neighbors = new ArrayList<>(aPairs.size());
        for (String[] pair : aPairs) {
            RoleHint hint = hintByLabel.get(firstLabel(pair[0]));
            neighbors.add(new DiscoveredNeighbor(pair[1], null, null, null, null, pair[0], hint));
        }
        return neighbors;
    }

    /** Lowercased first label of a dotted owner name — the cross-record join key. */
    private static String firstLabel(String ownerName) {
        int dot = ownerName.indexOf('.');
        String label = dot < 0 ? ownerName : ownerName.substring(0, dot);
        return label.toLowerCase(Locale.ROOT);
    }

    /**
     * First {@code model=} entry (key case-insensitive) among the TXT rdata's
     * 1-byte-length-prefixed strings, or null. {@code md=} is not consumed yet.
     */
    private static String findModelValue(byte[] payload, int rdataStart, int rdlength) {
        int pos = rdataStart;
        int end = rdataStart + rdlength;
        while (pos < end) {
            int len = payload[pos] & 0xFF;
            if (pos + 1 + len > end) {
                break; // truncated TXT entry — keep nothing further
            }
            String entry = new String(payload, pos + 1, len, StandardCharsets.UTF_8);
            int eq = entry.indexOf('=');
            if (eq > 0 && entry.substring(0, eq).equalsIgnoreCase("model")) {
                return entry.substring(eq + 1);
            }
            pos += 1 + len;
        }
        return null;
    }

    /**
     * Chassis mapping by case-insensitive model prefix: MacBook* → LAPTOP_CHASSIS;
     * iMac*, Macmini*, MacPro* → DESKTOP_CHASSIS. Ambiguous models (e.g. Mac14,2)
     * conservatively yield no hint.
     */
    private static RoleHint mapModelToHint(String model) {
        if (model == null) {
            return null;
        }
        String m = model.toLowerCase(Locale.ROOT);
        if (m.startsWith("macbook")) {
            return RoleHint.LAPTOP_CHASSIS;
        }
        if (m.startsWith("imac") || m.startsWith("macmini") || m.startsWith("macpro")) {
            return RoleHint.DESKTOP_CHASSIS;
        }
        return null;
    }

    /**
     * Structural name skip: never follows pointers (a compression pointer is two bytes
     * in place). Returns the offset just past the name, or -1 on truncation or a
     * reserved label type — the caller stops the datagram.
     */
    private static int skipName(byte[] payload, int pos) {
        while (true) {
            if (pos >= payload.length) {
                return -1;
            }
            int len = payload[pos] & 0xFF;
            if (len == 0) {
                return pos + 1;
            }
            if ((len & 0xC0) == 0xC0) {
                return pos + 2 <= payload.length ? pos + 2 : -1;
            }
            if ((len & 0xC0) != 0) {
                return -1; // reserved label types 0x40/0x80
            }
            pos += 1 + len;
        }
    }

    /**
     * Decompressed name VALUE with the trailing dot, or null on any DoS-bound
     * violation: a pointer whose target is not strictly backward, more than
     * {@value #MAX_POINTER_JUMPS} jumps, an assembled name over
     * {@value #MAX_NAME_BYTES} bytes, or truncation. A null only discards this
     * record's name — the structural walk continues independently.
     */
    private static String readNameValue(byte[] payload, int pos) {
        StringBuilder name = new StringBuilder();
        int cur = pos;
        int jumps = 0;
        int assembled = 0;
        while (true) {
            if (cur >= payload.length) {
                return null;
            }
            int len = payload[cur] & 0xFF;
            if (len == 0) {
                return name.toString();
            }
            if ((len & 0xC0) == 0xC0) {
                if (cur + 1 >= payload.length) {
                    return null;
                }
                int target = ((len & 0x3F) << 8) | (payload[cur + 1] & 0xFF);
                if (target >= cur) {
                    return null; // forward or self pointer — decompression bomb guard
                }
                if (++jumps > MAX_POINTER_JUMPS) {
                    return null;
                }
                cur = target;
                continue;
            }
            if ((len & 0xC0) != 0) {
                return null; // reserved label types 0x40/0x80
            }
            if (cur + 1 + len > payload.length) {
                return null;
            }
            assembled += len + 1;
            if (assembled > MAX_NAME_BYTES) {
                return null;
            }
            name.append(new String(payload, cur + 1, len, StandardCharsets.UTF_8)).append('.');
            cur += 1 + len;
        }
    }

    private static int readU16(byte[] buf, int offset) {
        return ((buf[offset] & 0xFF) << 8) | (buf[offset + 1] & 0xFF);
    }
}
