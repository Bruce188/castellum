package io.castellum.discovery;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Fully synthetic unit tests for {@link ConnTableReader}.
 *
 * <p><strong>No test reads the host's real {@code /proc/net}.</strong> Each test
 * writes realistic kernel-format fixtures into a {@code @TempDir} and points the
 * reader at it via the injectable proc-dir constructor.
 *
 * <p>Little-endian reminders: {@code B901A8C0} → 192.168.1.185, {@code 08080808} →
 * 8.8.8.8, {@code 0100007F} → 127.0.0.1. IPv6 fields are four little-endian 32-bit
 * words, e.g. {@code 60480120 00006048 00000000 88880000} → 2001:4860:4860::8888.
 */
class ConnTableReaderTest {

    @TempDir
    Path procDir;

    private static final String TCP_HEADER =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
    private static final String UDP_HEADER =
        "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops";

    /** Remote ceiling high enough that no fixture here triggers truncation. */
    private static final int NO_TRUNCATION = 512;

    private List<DiscoveredNeighbor> readWith(String fileName, String content) throws IOException {
        Files.writeString(procDir.resolve(fileName), content);
        return new ConnTableReader(procDir.toString(), NO_TRUNCATION).read();
    }

    private static List<String> ips(List<DiscoveredNeighbor> neighbors) {
        return neighbors.stream().map(DiscoveredNeighbor::ipAddress).toList();
    }

    @Test
    void read_tcp_keepsOnlyEstablishedRemotesAndSkipsLoopback() throws IOException {
        // Row 0: ESTABLISHED to 192.168.1.185 (B901A8C0) — kept
        // Row 1: LISTEN (0A), zero remote — excluded
        // Row 2: ESTABLISHED to 8.8.8.8 — kept
        // Row 3: ESTABLISHED to loopback 127.0.0.1 — excluded
        // Row 4: TIME_WAIT (06) to 9.9.9.9 — excluded by state
        List<DiscoveredNeighbor> result = readWith("tcp", String.join("\n",
            TCP_HEADER,
            "   0: 3500A8C0:0016 B901A8C0:D2A4 01 00000000:00000000 02:00097A4F 00000000     0        0 12345 4 0000000000000000 20 4 31 10 -1",
            "   1: 3500A8C0:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0",
            "   2: 3500A8C0:A1B2 08080808:01BB 01 00000000:00000000 02:00012345 00000000  1000        0 12347 2 0000000000000000 20 4 30 10 -1",
            "   3: 0100007F:0BB8 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 12348 1 0000000000000000 20 4 30 10 -1",
            "   4: 3500A8C0:C123 09090909:01BB 06 00000000:00000000 03:00000F2D 00000000     0        0 0 3 0000000000000000",
            ""));

        assertThat(ips(result)).containsExactly("192.168.1.185", "8.8.8.8");
        // Connection-table neighbors carry only the IP — every other slot is null
        DiscoveredNeighbor first = result.get(0);
        assertThat(first.macAddress()).isNull();
        assertThat(first.hwType()).isNull();
        assertThat(first.flags()).isNull();
        assertThat(first.iface()).isNull();
        assertThat(first.hostname()).isNull();
    }

    @Test
    void read_tcp6_decodesGroupsAndSkipsLoopbackAndLinkLocal() throws IOException {
        // Row 0: LISTEN, unspecified :: remote — excluded
        // Row 1: ESTABLISHED to 2001:4860:4860::8888 — kept
        // Row 2: ESTABLISHED to fe80::1 (link-local) — excluded
        // Row 3: ESTABLISHED to ::1 (loopback) — excluded
        List<DiscoveredNeighbor> result = readWith("tcp6", String.join("\n",
            TCP_HEADER,
            "   0: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22000 1 0000000000000000 100 0 0 10 0",
            "   1: 0000000000000000FFFF00003500A8C0:9C40 60480120000060480000000088880000:01BB 01 00000000:00000000 02:000004D2 00000000  1000        0 22001 2 0000000000000000 20 4 30 10 -1",
            "   2: 00000000000000000000000000000000:1F90 000080FE000000000000000001000000:0203 01 00000000:00000000 00:00000000 00000000     0        0 22002 1 0000000000000000 20 4 30 10 -1",
            "   3: 00000000000000000000000001000000:8000 00000000000000000000000001000000:0277 01 00000000:00000000 00:00000000 00000000     0        0 22003 1 0000000000000000 20 4 30 10 -1",
            ""));

        String expected = InetAddress.getByName("2001:4860:4860::8888").getHostAddress();
        assertThat(ips(result)).containsExactly(expected);
    }

    @Test
    void read_udpTables_keepOnlyNonZeroRemotes() throws IOException {
        // udp row 100: unconnected socket (zero remote) — excluded
        // udp row 101: connected to 1.1.1.1:53 — kept
        Files.writeString(procDir.resolve("udp"), String.join("\n",
            UDP_HEADER,
            "  100: 3500A8C0:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 30000 2 0000000000000000 0",
            "  101: 3500A8C0:E1F0 01010101:0035 01 00000000:00000000 00:00000000 00000000  1000        0 30001 2 0000000000000000 0",
            ""));
        // udp6 row 200: unconnected (zero remote) — excluded
        // udp6 row 201: connected to 2606:4700:4700::1111 — kept
        Files.writeString(procDir.resolve("udp6"), String.join("\n",
            UDP_HEADER,
            "  200: 00000000000000000000000000000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 31000 2 0000000000000000 0",
            "  201: 0000000000000000FFFF00003500A8C0:D2F0 00470626000000470000000011110000:0035 01 00000000:00000000 00:00000000 00000000  1000        0 31001 2 0000000000000000 0",
            ""));

        List<DiscoveredNeighbor> result = new ConnTableReader(procDir.toString(), NO_TRUNCATION).read();

        String expectedV6 = InetAddress.getByName("2606:4700:4700::1111").getHostAddress();
        assertThat(ips(result)).containsExactly("1.1.1.1", expectedV6);
    }

    @Test
    void read_sameRemoteAcrossTables_dedupedByIp() throws IOException {
        // 8.8.8.8 appears as an ESTABLISHED tcp remote AND a connected udp remote —
        // one read must emit it exactly once.
        Files.writeString(procDir.resolve("tcp"), String.join("\n",
            TCP_HEADER,
            "   0: 3500A8C0:A1B2 08080808:01BB 01 00000000:00000000 02:00012345 00000000  1000        0 12347 2 0000000000000000 20 4 30 10 -1",
            ""));
        Files.writeString(procDir.resolve("udp"), String.join("\n",
            UDP_HEADER,
            "  101: 3500A8C0:E1F0 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 30001 2 0000000000000000 0",
            ""));

        List<DiscoveredNeighbor> result = new ConnTableReader(procDir.toString(), NO_TRUNCATION).read();

        assertThat(ips(result)).containsExactly("8.8.8.8");
    }

    @Test
    void read_missingProcDir_returnsEmptyList() {
        ConnTableReader reader =
            new ConnTableReader(procDir.resolve("does-not-exist").toString(), NO_TRUNCATION);

        assertThat(reader.read()).isEmpty();
    }

    @Test
    void read_malformedLines_skippedWithoutThrowing() throws IOException {
        // Garbage rows (too few fields, non-hex remote, missing port separator) must be
        // skipped while the valid row still lands.
        List<DiscoveredNeighbor> result = readWith("tcp", String.join("\n",
            TCP_HEADER,
            "   0: garbage",
            "   1: 3500A8C0:0016 ZZZZZZZZ:01BB 01 00000000:00000000 00:00000000 00000000     0        0 1 1",
            "   2: 3500A8C0:0016 08080808 01 00000000:00000000 00:00000000 00000000     0        0 1 1",
            "   3: 3500A8C0:A1B2 B901A8C0:D2A4 01 00000000:00000000 02:00012345 00000000  1000        0 12347 2 0000000000000000 20 4 30 10 -1",
            ""));

        assertThat(ips(result)).containsExactly("192.168.1.185");
    }

    @Test
    void read_moreRemotesThanCap_truncatesToFirstNInFileOrderAfterDedupe() throws IOException {
        // Five ESTABLISHED rows but only four distinct remotes (1.1.1.1 repeats):
        // with the cap at 2, the duplicate must not consume cap budget — dedupe runs
        // first, then exactly the first two distinct remotes in file order survive.
        Files.writeString(procDir.resolve("tcp"), String.join("\n",
            TCP_HEADER,
            "   0: 3500A8C0:A1B2 01010101:01BB 01 00000000:00000000 02:00012345 00000000  1000        0 40000 2 0000000000000000 20 4 30 10 -1",
            "   1: 3500A8C0:A1B3 01010101:0050 01 00000000:00000000 02:00012345 00000000  1000        0 40001 2 0000000000000000 20 4 30 10 -1",
            "   2: 3500A8C0:A1B4 02020202:01BB 01 00000000:00000000 02:00012345 00000000  1000        0 40002 2 0000000000000000 20 4 30 10 -1",
            "   3: 3500A8C0:A1B5 03030303:01BB 01 00000000:00000000 02:00012345 00000000  1000        0 40003 2 0000000000000000 20 4 30 10 -1",
            "   4: 3500A8C0:A1B6 04040404:01BB 01 00000000:00000000 02:00012345 00000000  1000        0 40004 2 0000000000000000 20 4 30 10 -1",
            ""));

        List<DiscoveredNeighbor> result = new ConnTableReader(procDir.toString(), 2).read();

        assertThat(ips(result)).containsExactly("1.1.1.1", "2.2.2.2");
    }

    /**
     * Wrong-length hex address — {@code decodeHexAddress} returns null when the hex
     * portion of the remote address is neither 8 (IPv4) nor 32 (IPv6) chars. The row
     * must be silently skipped while the next valid row is still returned.
     *
     * <p>This exercises the {@code return null} branch at the bottom of
     * {@code decodeHexAddress} (the "unexpected length" guard) which is not reached by
     * the existing malformed-line test (that test has non-hex chars, triggering
     * {@code NumberFormatException}, not the length guard).
     *
     * <p>A 6-character hex portion ("AABBCC") is neither 8 nor 32 chars and contains
     * only valid hex digits, so it reaches the length guard and returns null.
     */
    @Test
    void read_wrongLengthHexAddress_skippedWithoutThrowing() throws IOException {
        // Row 0: 6-char hex remote (neither 8 nor 32) — wrong-length guard → skip
        // Row 1: valid ESTABLISHED row → kept (8.8.8.8)
        List<DiscoveredNeighbor> result = readWith("tcp", String.join("\n",
            TCP_HEADER,
            "   0: 3500A8C0:0016 AABBCC:01BB 01 00000000:00000000 00:00000000 00000000     0        0 1 1",
            "   1: 3500A8C0:A1B2 08080808:01BB 01 00000000:00000000 02:00012345 00000000  1000        0 12347 2 0000000000000000 20 4 30 10 -1",
            ""));

        assertThat(ips(result)).containsExactly("8.8.8.8");
    }

    /**
     * 16-char hex (halfway to IPv6 length) — also wrong-length, also skipped.
     * Ensures the guard is not confused between IPv4 (8), some intermediate value (16),
     * and IPv6 (32).
     */
    @Test
    void read_intermediateHexLength_skippedWithoutThrowing() throws IOException {
        // Row 0: 16-char hex (not 8 or 32) — wrong-length guard → skip
        // Row 1: valid → kept (1.1.1.1)
        List<DiscoveredNeighbor> result = readWith("tcp", String.join("\n",
            TCP_HEADER,
            "   0: 3500A8C0:0016 AABBCCDDEEFF0011:01BB 01 00000000:00000000 00:00000000 00000000     0        0 1 1",
            "   1: 3500A8C0:A1B2 01010101:01BB 01 00000000:00000000 02:00012345 00000000  1000        0 12347 2 0000000000000000 20 4 30 10 -1",
            ""));

        assertThat(ips(result)).containsExactly("1.1.1.1");
    }

    @Test
    void read_remotesAtOrBelowCap_returnedUntruncated() throws IOException {
        List<DiscoveredNeighbor> result = readWith("tcp", String.join("\n",
            TCP_HEADER,
            "   0: 3500A8C0:A1B2 01010101:01BB 01 00000000:00000000 02:00012345 00000000  1000        0 41000 2 0000000000000000 20 4 30 10 -1",
            "   1: 3500A8C0:A1B3 02020202:01BB 01 00000000:00000000 02:00012345 00000000  1000        0 41001 2 0000000000000000 20 4 30 10 -1",
            ""));

        assertThat(ips(result)).containsExactly("1.1.1.1", "2.2.2.2");
    }
}
