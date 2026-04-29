package io.castellum.discovery;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PcapSnifferReplayTest {

    @Test
    void replay_arpFixture_decodesArpRequests_returnsNeighbors() throws Exception {
        PcapSniffer sniffer = new PcapSniffer("arp");
        File fixture = new File("src/test/resources/discovery/arp-self-discovery.pcap");
        assertThat(fixture).exists();

        List<DiscoveredNeighbor> neighbors = sniffer.replay(fixture);
        assertThat(neighbors).isNotEmpty();
        assertThat(neighbors).anyMatch(n ->
            n.ipAddress() != null &&
            n.ipAddress().matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$") &&
            n.macAddress() != null
        );
    }

    @Test
    void replay_emptyPcap_returnsEmptyList(@TempDir Path tmp) throws Exception {
        // Create a minimal pcap with header but zero records
        Path emptyPcap = tmp.resolve("empty.pcap");
        byte[] globalHdr = buildPcapGlobalHeader();
        Files.write(emptyPcap, globalHdr);

        PcapSniffer sniffer = new PcapSniffer("arp");
        List<DiscoveredNeighbor> neighbors = sniffer.replay(emptyPcap.toFile());
        assertThat(neighbors).isEmpty();
    }

    @Test
    void live_handle_close_inFinally() {
        PcapSniffer sniffer = new PcapSniffer("arp");
        // An interface that does not exist should cause PcapNativeException
        assertThatThrownBy(() -> sniffer.sniff("nonexistent99", 1))
            .isInstanceOf(PcapNativeException.class);
    }

    private byte[] buildPcapGlobalHeader() {
        ByteBuffer buf = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(0xa1b2c3d4); // magic
        buf.putShort((short) 2); // major
        buf.putShort((short) 4); // minor
        buf.putInt(0);           // thiszone
        buf.putInt(0);           // sigfigs
        buf.putInt(65535);       // snaplen
        buf.putInt(1);           // LINKTYPE_ETHERNET
        return buf.array();
    }
}
