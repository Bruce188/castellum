package io.castellum.discovery;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class ArpCacheReaderTest {

    private static final String FIXTURE = "src/test/resources/discovery/proc-net-arp.txt";

    @Test
    void read_validFixture_returnsEntries() {
        ArpCacheReader reader = new ArpCacheReader(FIXTURE);
        List<DiscoveredNeighbor> entries = reader.read();
        // Fixture has 2 valid entries: 192.168.1.1 and 192.168.1.99
        // 192.168.1.42 is zero-MAC (filtered), not.an.ip.addr is malformed (filtered)
        assertThat(entries).hasSize(2);
        assertThat(entries).anyMatch(e -> e.ipAddress().equals("192.168.1.1") && e.macAddress().equals("aa:bb:cc:dd:ee:ff"));
        assertThat(entries).anyMatch(e -> e.ipAddress().equals("192.168.1.99") && e.macAddress().equals("11:22:33:44:55:66"));
    }

    @Test
    void read_skipsHeaderRow() {
        ArpCacheReader reader = new ArpCacheReader(FIXTURE);
        List<DiscoveredNeighbor> entries = reader.read();
        assertThat(entries).noneMatch(e -> "IP address".equals(e.ipAddress()));
    }

    @Test
    void read_filtersIncompleteMac() {
        ArpCacheReader reader = new ArpCacheReader(FIXTURE);
        List<DiscoveredNeighbor> entries = reader.read();
        assertThat(entries).noneMatch(e -> "00:00:00:00:00:00".equalsIgnoreCase(e.macAddress()));
    }

    @Test
    void read_tolerantOfBlankLines(@TempDir Path tmp) throws Exception {
        Path fixture = tmp.resolve("arp-blanks.txt");
        Files.writeString(fixture, String.join("\n",
            "",
            "IP address       HW type     Flags       HW address            Mask     Device",
            "",
            "10.0.0.1      0x1         0x2         ca:fe:ba:be:00:01     *        eth0",
            "",
            "10.0.0.2      0x1         0x2         ca:fe:ba:be:00:02     *        eth0",
            ""
        ), StandardCharsets.UTF_8);

        ArpCacheReader reader = new ArpCacheReader(fixture.toString());
        List<DiscoveredNeighbor> entries = reader.read();
        assertThat(entries).hasSize(2);
    }

    @Test
    void read_malformedLine_skippedNotThrown() {
        ArpCacheReader reader = new ArpCacheReader(FIXTURE);
        assertThatCode(() -> {
            List<DiscoveredNeighbor> entries = reader.read();
            // The "not.an.ip.addr" row is skipped; only 2 valid rows returned
            assertThat(entries).hasSize(2);
        }).doesNotThrowAnyException();
    }

    @Test
    void read_fileMissing_returnsEmptyList() {
        String nonExistent = "/tmp/definitely-does-not-exist-" + UUID.randomUUID();
        ArpCacheReader reader = new ArpCacheReader(nonExistent);
        assertThatCode(() -> {
            List<DiscoveredNeighbor> entries = reader.read();
            assertThat(entries).isEmpty();
        }).doesNotThrowAnyException();
    }
}
