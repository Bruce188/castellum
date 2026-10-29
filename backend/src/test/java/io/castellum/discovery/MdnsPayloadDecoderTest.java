package io.castellum.discovery;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/**
 * Datagram-level tests for the raw mDNS payload decoder.
 *
 * <p>DNS messages are assembled byte-by-byte with in-test builders: 12-byte
 * header (ID 0x0000, big-endian flags — QR is the 0x8000 bit — then
 * QD/AN/NS/AR counts), label-encoded names (1-byte length + bytes, 0x00
 * terminator, {@code 0xC0}-masked 2-byte compression pointers), then resource
 * records: owner name, TYPE (2), CLASS (2 — the mDNS cache-flush bit rides
 * 0x8000 and must be masked), TTL (4), RDLENGTH (2), RDATA. A records are
 * TYPE 1 / RDLENGTH 4; TXT records are TYPE 16 with 1-byte-length-prefixed
 * strings; AAAA (28) is skipped for now.
 */
class MdnsPayloadDecoderTest {

    private final MdnsPayloadDecoder decoder = new MdnsPayloadDecoder();

    private static final int FLAGS_RESPONSE = 0x8400;   // QR=1, AA=1
    private static final int FLAGS_QUERY = 0x0000;

    // ────────────────────────────────────────────────────────────────────────
    // In-test DNS builders — offsets and codes are wire literals
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

    private static byte[] be32(long v) {
        return new byte[]{(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) (v & 0xFF)};
    }

    private static byte[] ip4(int a, int b, int c, int d) {
        return new byte[]{(byte) a, (byte) b, (byte) c, (byte) d};
    }

    /** 12-byte DNS header: ID 0, flags, QD/AN/NS/AR counts. */
    private static byte[] dnsHeader(int flags, int qd, int an, int ns, int ar) {
        return concat(be16(0), be16(flags), be16(qd), be16(an), be16(ns), be16(ar));
    }

    /** Label-encoded name from dotted form ("bruce-mbp.local." → labels + 0x00). */
    private static byte[] name(String dotted) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String label : dotted.split("\\.")) {
            if (label.isEmpty()) {
                continue;
            }
            byte[] bytes = label.getBytes(StandardCharsets.UTF_8);
            out.write(bytes.length);
            out.writeBytes(bytes);
        }
        out.write(0);
        return out.toByteArray();
    }

    /** 2-byte compression pointer to the given offset. */
    private static byte[] pointer(int offset) {
        return new byte[]{(byte) (0xC0 | (offset >> 8)), (byte) (offset & 0xFF)};
    }

    /** Question entry: name + QTYPE + QCLASS. */
    private static byte[] question(byte[] nameBytes, int type, int clazz) {
        return concat(nameBytes, be16(type), be16(clazz));
    }

    /** Resource record with RDLENGTH computed from the actual rdata. */
    private static byte[] record(byte[] nameBytes, int type, int clazz, long ttl, byte[] rdata) {
        return concat(nameBytes, be16(type), be16(clazz), be32(ttl), be16(rdata.length), rdata);
    }

    /** Resource record with a deliberately lying RDLENGTH. */
    private static byte[] recordWithRdlen(byte[] nameBytes, int type, int clazz, long ttl,
                                          int declaredRdlen, byte[] rdata) {
        return concat(nameBytes, be16(type), be16(clazz), be32(ttl), be16(declaredRdlen), rdata);
    }

    /** TXT rdata: each entry as a 1-byte-length-prefixed string. */
    private static byte[] txtRdata(String... entries) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String e : entries) {
            byte[] bytes = e.getBytes(StandardCharsets.UTF_8);
            out.write(bytes.length);
            out.writeBytes(bytes);
        }
        return out.toByteArray();
    }

    private static byte[] aRecord(String owner, int a, int b, int c, int d) {
        return record(name(owner), 1, 1, 120, ip4(a, b, c, d));
    }

    private static byte[] deviceInfoTxt(String hostLabel, String... entries) {
        return record(name(hostLabel + "._device-info._tcp.local."), 16, 1, 4500, txtRdata(entries));
    }

    // ────────────────────────────────────────────────────────────────────────
    // 1. Response with one A record — ip + full owner-name hostname, no hint
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_singleARecord_yieldsIpAndHostnameNeighbor() {
        byte[] payload = concat(
            dnsHeader(FLAGS_RESPONSE, 0, 1, 0, 0),
            aRecord("bruce-mbp.local.", 192, 168, 1, 60));

        List<DiscoveredNeighbor> result = decoder.decode(payload);

        assertThat(result).hasSize(1);
        DiscoveredNeighbor n = result.get(0);
        assertThat(n.ipAddress()).isEqualTo("192.168.1.60");
        assertThat(n.hostname())
            .as("hostname is the full owner name including the trailing dot")
            .isEqualTo("bruce-mbp.local.");
        assertThat(n.macAddress()).isNull();
        assertThat(n.roleHint()).isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 2. Query datagram (QR=0) carrying A-shaped records — empty
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_queryDatagram_returnsEmpty() {
        byte[] payload = concat(
            dnsHeader(FLAGS_QUERY, 0, 1, 0, 0),
            aRecord("bruce-mbp.local.", 192, 168, 1, 60));

        assertThat(decoder.decode(payload))
            .as("QR bit 0 — queries are never evidence of an answering host")
            .isEmpty();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 3. A + _device-info TXT model=MacBookPro18,3 — LAPTOP_CHASSIS attached
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_aPlusDeviceInfoTxtMacBook_laptopChassisHint() {
        byte[] payload = concat(
            dnsHeader(FLAGS_RESPONSE, 0, 1, 0, 1),
            aRecord("bruce-mbp.local.", 192, 168, 1, 60),
            deviceInfoTxt("bruce-mbp", "model=MacBookPro18,3"));

        List<DiscoveredNeighbor> result = decoder.decode(payload);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.1.60");
        assertThat(result.get(0).roleHint())
            .as("model=MacBook* under _device-info maps to LAPTOP_CHASSIS")
            .isEqualTo(RoleHint.LAPTOP_CHASSIS);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 4. iMac / Macmini models — DESKTOP_CHASSIS
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_iMacAndMacminiModels_desktopChassisHint() {
        byte[] imac = concat(
            dnsHeader(FLAGS_RESPONSE, 0, 1, 0, 1),
            aRecord("study-imac.local.", 192, 168, 1, 61),
            deviceInfoTxt("study-imac", "model=iMac21,1"));
        List<DiscoveredNeighbor> imacResult = decoder.decode(imac);
        assertThat(imacResult).hasSize(1);
        assertThat(imacResult.get(0).roleHint()).isEqualTo(RoleHint.DESKTOP_CHASSIS);

        byte[] macmini = concat(
            dnsHeader(FLAGS_RESPONSE, 0, 1, 0, 1),
            aRecord("shelf-mini.local.", 192, 168, 1, 62),
            deviceInfoTxt("shelf-mini", "model=Macmini9,1"));
        List<DiscoveredNeighbor> miniResult = decoder.decode(macmini);
        assertThat(miniResult).hasSize(1);
        assertThat(miniResult.get(0).roleHint()).isEqualTo(RoleHint.DESKTOP_CHASSIS);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 5. Ambiguous Apple-Silicon model (Mac14,2) — NO hint
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_ambiguousMacModel_noHint() {
        byte[] payload = concat(
            dnsHeader(FLAGS_RESPONSE, 0, 1, 0, 1),
            aRecord("new-mac.local.", 192, 168, 1, 63),
            deviceInfoTxt("new-mac", "model=Mac14,2"));

        List<DiscoveredNeighbor> result = decoder.decode(payload);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).roleHint())
            .as("Mac14,2 is chassis-ambiguous — the conservative pin is no hint")
            .isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 6. _device-info TXT with no matching A record — dropped (unkeyable)
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_deviceInfoTxtWithoutMatchingARecord_yieldsNothing() {
        byte[] payload = concat(
            dnsHeader(FLAGS_RESPONSE, 0, 1, 0, 0),
            deviceInfoTxt("ghost-mbp", "model=MacBookPro18,3"));

        assertThat(decoder.decode(payload))
            .as("a hint with no A record in the same datagram has no IP key")
            .isEmpty();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 7. Compressed owner name (backward pointer into the question section)
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_compressedOwnerName_decodesHostname() {
        // Question name starts at offset 12; the answer's owner is a pointer to it.
        byte[] payload = concat(
            dnsHeader(FLAGS_RESPONSE, 1, 1, 0, 0),
            question(name("bruce-mbp.local."), 1, 1),
            record(pointer(12), 1, 1, 120, ip4(192, 168, 1, 60)));

        List<DiscoveredNeighbor> result = decoder.decode(payload);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.1.60");
        assertThat(result.get(0).hostname())
            .as("backward compression pointers must decompress to the full name")
            .isEqualTo("bruce-mbp.local.");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 8. Self-referencing pointer — no throw, that name discarded, earlier
    //    neighbor kept
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_selfReferencingPointer_noThrowEarlierNeighborKept() {
        byte[] first = aRecord("bruce-mbp.local.", 192, 168, 1, 60);
        int secondRecordOffset = 12 + first.length;
        // Owner name is a pointer to its own offset — target NOT strictly backward.
        byte[] second = record(pointer(secondRecordOffset), 1, 1, 120, ip4(192, 168, 1, 99));
        byte[] payload = concat(dnsHeader(FLAGS_RESPONSE, 0, 2, 0, 0), first, second);

        List<DiscoveredNeighbor> result = assertTimeoutPreemptively(
            Duration.ofSeconds(5), () -> decoder.decode(payload));

        assertThat(result)
            .as("the self-pointing record's name is discarded; the first neighbor survives")
            .hasSize(1);
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.1.60");
        assertThat(result.get(0).hostname()).isEqualTo("bruce-mbp.local.");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 9. Forward pointer (target ≥ pointer offset) — name rejected, structural
    //    walk continues to the next record
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_forwardPointer_nameRejectedWalkContinues() {
        // First record's owner pointer (at offset 12) points FORWARD to offset 100.
        byte[] first = record(pointer(100), 1, 1, 120, ip4(192, 168, 1, 99));
        byte[] second = aRecord("bruce-mbp.local.", 192, 168, 1, 60);
        byte[] payload = concat(dnsHeader(FLAGS_RESPONSE, 0, 2, 0, 0), first, second);

        List<DiscoveredNeighbor> result = assertTimeoutPreemptively(
            Duration.ofSeconds(5), () -> decoder.decode(payload));

        assertThat(result)
            .as("forward pointers reject the name VALUE but the walk continues")
            .hasSize(1);
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.1.60");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 10. RDLENGTH overruns the datagram — stop, keep collected, no throw
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_rdlengthOverrun_stopsKeepsCollected() {
        byte[] first = aRecord("bruce-mbp.local.", 192, 168, 1, 60);
        byte[] overrunning = recordWithRdlen(name("evil.local."), 1, 1, 120, 200, ip4(10, 0, 0, 1));
        byte[] payload = concat(dnsHeader(FLAGS_RESPONSE, 0, 2, 0, 0), first, overrunning);

        List<DiscoveredNeighbor> result = decoder.decode(payload);

        assertThat(result)
            .as("structural overrun stops the datagram, keeping earlier neighbors")
            .hasSize(1);
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.1.60");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 11. Case-insensitive model key/prefix; md= key alone yields no hint
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_caseInsensitiveModelKeyAndPrefix_mdKeyIgnored() {
        byte[] upperCase = concat(
            dnsHeader(FLAGS_RESPONSE, 0, 1, 0, 1),
            aRecord("air.local.", 192, 168, 1, 64),
            deviceInfoTxt("air", "MODEL=macbookair10,1"));
        List<DiscoveredNeighbor> upperResult = decoder.decode(upperCase);
        assertThat(upperResult).hasSize(1);
        assertThat(upperResult.get(0).roleHint())
            .as("key and value prefix match case-insensitively")
            .isEqualTo(RoleHint.LAPTOP_CHASSIS);

        byte[] mdKey = concat(
            dnsHeader(FLAGS_RESPONSE, 0, 1, 0, 1),
            aRecord("air.local.", 192, 168, 1, 64),
            deviceInfoTxt("air", "md=MacBookAir10,1"));
        List<DiscoveredNeighbor> mdResult = decoder.decode(mdKey);
        assertThat(mdResult).hasSize(1);
        assertThat(mdResult.get(0).roleHint())
            .as("only the model= key is consumed — md= is not")
            .isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 12. AAAA-only response — empty (IPv4-only pin)
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_aaaaOnlyResponse_returnsEmpty() {
        byte[] ipv6 = new byte[16];
        ipv6[0] = (byte) 0xfd;
        ipv6[15] = 0x01;
        byte[] payload = concat(
            dnsHeader(FLAGS_RESPONSE, 0, 1, 0, 0),
            record(name("bruce-mbp.local."), 28, 1, 120, ipv6));

        assertThat(decoder.decode(payload))
            .as("AAAA (type 28) is skipped — IPv4-only for now")
            .isEmpty();
    }

    // ────────────────────────────────────────────────────────────────────────
    // 13. CLASS=0x8001 (cache-flush bit) — parses identically
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_cacheFlushClassBit_parsesIdentically() {
        byte[] payload = concat(
            dnsHeader(FLAGS_RESPONSE, 0, 1, 0, 0),
            record(name("bruce-mbp.local."), 1, 0x8001, 120, ip4(192, 168, 1, 60)));

        List<DiscoveredNeighbor> result = decoder.decode(payload);

        assertThat(result)
            .as("the mDNS cache-flush bit rides CLASS 0x8000 and must be masked")
            .hasSize(1);
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.1.60");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 14. ANCOUNT=10 but one record present — bounds-stop, one neighbor
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_ancountOverclaim_boundsStopOneNeighbor() {
        byte[] payload = concat(
            dnsHeader(FLAGS_RESPONSE, 0, 10, 0, 0),
            aRecord("bruce-mbp.local.", 192, 168, 1, 60));

        List<DiscoveredNeighbor> result = assertTimeoutPreemptively(
            Duration.ofSeconds(5), () -> decoder.decode(payload));

        assertThat(result)
            .as("counts are claims, not trusted — the walk stops at the datagram end")
            .hasSize(1);
        assertThat(result.get(0).ipAddress()).isEqualTo("192.168.1.60");
    }

    // ────────────────────────────────────────────────────────────────────────
    // 15. model= TXT NOT under _device-info — no hint (owner-suffix gate)
    // ────────────────────────────────────────────────────────────────────────

    @Test
    void decode_modelTxtNotUnderDeviceInfo_noHint() {
        byte[] payload = concat(
            dnsHeader(FLAGS_RESPONSE, 0, 1, 0, 1),
            aRecord("bruce-mbp.local.", 192, 168, 1, 60),
            record(name("bruce-mbp._http._tcp.local."), 16, 1, 4500,
                txtRdata("model=MacBookPro18,3")));

        List<DiscoveredNeighbor> result = decoder.decode(payload);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).roleHint())
            .as("only TXT owners ending ._device-info._tcp.local. carry chassis hints")
            .isNull();
    }
}
