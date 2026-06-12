package io.castellum.discovery;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * CDP (Cisco Discovery Protocol) frame decoder.
 *
 * <p>CDP is not an ethertype protocol — it rides IEEE 802.3 frames (length field at
 * offset 12, value ≤ 1500, optionally behind one 802.1Q tag) with LLC/SNAP encapsulation:
 * LLC {@code AA AA 03}, SNAP OUI {@code 00 00 0C}, SNAP protocol ID {@code 0x2000}. The
 * protocol-ID gate is mandatory — VTP/DTP/PAgP/UDLD share the {@code 01:00:0c:cc:cc:cc}
 * destination MAC and pass {@link CdpCapture}'s BPF filter. Parses the TLV stream
 * (4-byte header: 2-byte BE type, 2-byte BE length <em>including</em> the header) into
 * exactly one {@link DiscoveredNeighbor}:
 * <ul>
 *   <li>Ethernet source MAC (bytes 6-11) → {@code macAddress}, lowercase colon-separated
 *       {@code %02x} via {@link MacFormat} — CDP has no chassis-ID TLV carrying a MAC, so
 *       the frame source is the only (and a per-port stable) MAC available;</li>
 *   <li>Device ID ({@code 0x0001}) → {@code hostname} (trimmed, blank → null, first wins);</li>
 *   <li>Addresses ({@code 0x0002}) and Management Address ({@code 0x0016}) share one
 *       address-block wire format → {@code ipAddress}: the first IPv4 entry (NLPID
 *       {@code 0xCC}, 4-byte address) across both TLV types in stream order wins; non-IPv4
 *       entries are skipped by their self-describing size, never rejected;</li>
 *   <li>version, TTL and checksum are ignored — Cisco's odd-length checksum quirk falsely
 *       rejects valid frames under a textbook ones'-complement verifier, and the device
 *       demonstrably exists regardless.</li>
 * </ul>
 *
 * <p>Malformed input never throws: a wrong length field/LLC/SNAP/protocol ID or a frame too
 * short to hold the headers yields an empty list; TLV parsing is bounded by the 802.3
 * length field (pad bytes beyond it are never parsed), and a TLV whose declared length is
 * below its own 4-byte header or overruns the bound ends parsing while keeping the fields
 * collected so far. A malformed address block abandons only that TLV; the walk continues.
 */
@Service
public class CdpDecoder {

    private static final int MAX_8023_LENGTH = 1500;
    private static final int SNAP_PID_CDP = 0x2000;

    private static final int TLV_DEVICE_ID = 0x0001;
    private static final int TLV_ADDRESSES = 0x0002;
    private static final int TLV_MGMT_ADDRESS = 0x0016;

    /** LLC(3) + SNAP OUI(3) + SNAP PID(2) + CDP version(1) + TTL(1) + checksum(2). */
    private static final int LLC_TO_TLV_OFFSET = 12;

    public List<DiscoveredNeighbor> decode(byte[] frame, String iface) {
        if (frame == null || frame.length < 26) {
            return List.of();
        }
        EtherFraming framing = EtherFraming.of(frame);
        if (framing == null || framing.typeOrLength() > MAX_8023_LENGTH) {
            return List.of(); // not an 802.3 length field — not CDP
        }
        int llcOffset = framing.payloadStart();
        int lengthField = framing.typeOrLength();
        if (frame.length < llcOffset + LLC_TO_TLV_OFFSET) {
            return List.of();
        }
        if ((frame[llcOffset] & 0xFF) != 0xAA
                || (frame[llcOffset + 1] & 0xFF) != 0xAA
                || (frame[llcOffset + 2] & 0xFF) != 0x03) {
            return List.of(); // not LLC/SNAP
        }
        if (frame[llcOffset + 3] != 0x00 || frame[llcOffset + 4] != 0x00
                || (frame[llcOffset + 5] & 0xFF) != 0x0C) {
            return List.of(); // not the Cisco SNAP OUI
        }
        if (readU16(frame, llcOffset + 6) != SNAP_PID_CDP) {
            return List.of(); // VTP/DTP/PAgP/UDLD share the dst MAC — not CDP
        }

        String mac = MacFormat.format(frame, 6);
        String hostname = null;
        String ip = null;

        // The 802.3 length field counts from the LLC header and is the authoritative
        // payload end — pad bytes extending the frame to 60 are never parsed as TLVs.
        int tlvEnd = Math.min(frame.length, llcOffset + lengthField);
        int offset = llcOffset + LLC_TO_TLV_OFFSET;
        while (offset + 4 <= tlvEnd) {
            int type = readU16(frame, offset);
            int length = readU16(frame, offset + 2); // includes the 4-byte header
            if (length < 4 || offset + length > tlvEnd) {
                break; // malformed or overrunning TLV — keep fields collected so far
            }
            // Value bytes are only materialized for consumed TLV types — the many
            // ignored TLVs (Port ID, capabilities, platform, …) cost no allocation.
            switch (type) {
                case TLV_DEVICE_ID -> {
                    if (hostname == null) {
                        String name = new String(frame, offset + 4, length - 4,
                            StandardCharsets.UTF_8).trim();
                        hostname = name.isEmpty() ? null : name;
                    }
                }
                case TLV_ADDRESSES, TLV_MGMT_ADDRESS -> {
                    // Same wire format; first IPv4 across both TLV types in stream order wins.
                    if (ip == null) {
                        ip = parseAddressBlock(Arrays.copyOfRange(frame, offset + 4, offset + length));
                    }
                }
                default -> { /* Port ID, capabilities, platform, … ignored */ }
            }
            offset += length;
        }

        return List.of(new DiscoveredNeighbor(ip, mac, null, null, iface, hostname));
    }

    /**
     * Address block ({@code 0x0002}/{@code 0x0016} TLV value): 4-byte BE entry count, then
     * per entry {@code protocolType} (1 byte: 1 = NLPID, 2 = 802.2), {@code protocolLength}
     * (1 byte), {@code protocol} bytes, {@code addressLength} (2 bytes BE), address bytes.
     * Returns the first IPv4 entry ({@code protocolType == 1}, {@code protocolLength == 1},
     * protocol {@code 0xCC}, {@code addressLength == 4}); all other entries (IPv6 802.2 long
     * form, CLNS NLPID {@code 0x81}, …) are skipped by their self-describing size. Every
     * read is bounds-checked, so a bogus count cannot overrun or spin; a malformed block
     * yields null and only abandons this TLV.
     */
    private static String parseAddressBlock(byte[] value) {
        if (value.length < 4) {
            return null;
        }
        long count = readU32(value, 0);
        int pos = 4;
        for (long entry = 0; entry < count; entry++) {
            if (pos + 2 > value.length) {
                return null;
            }
            int protocolType = value[pos] & 0xFF;
            int protocolLength = value[pos + 1] & 0xFF;
            pos += 2;
            if (pos + protocolLength + 2 > value.length) {
                return null;
            }
            int protocolStart = pos;
            pos += protocolLength;
            int addressLength = readU16(value, pos);
            pos += 2;
            if (pos + addressLength > value.length) {
                return null;
            }
            if (protocolType == 1 && protocolLength == 1
                    && (value[protocolStart] & 0xFF) == 0xCC && addressLength == 4) {
                return WireAddress.toLiteral(Arrays.copyOfRange(value, pos, pos + 4));
            }
            pos += addressLength;
        }
        return null;
    }

    private static int readU16(byte[] buf, int offset) {
        return ((buf[offset] & 0xFF) << 8) | (buf[offset + 1] & 0xFF);
    }

    private static long readU32(byte[] buf, int offset) {
        return ((long) (buf[offset] & 0xFF) << 24)
            | ((buf[offset + 1] & 0xFF) << 16)
            | ((buf[offset + 2] & 0xFF) << 8)
            | (buf[offset + 3] & 0xFF);
    }
}
