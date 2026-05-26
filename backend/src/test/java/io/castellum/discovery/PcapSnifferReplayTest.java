package io.castellum.discovery;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.pcap4j.core.PcapNativeException;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PcapSnifferReplayTest {

    @Test
    void replay_arpFixture_decodesArpRequests_returnsNeighbors(@TempDir Path tmp) throws Exception {
        // Synthetic single-record pcap built at runtime — replaces the prior committed binary
        // fixture (arp-self-discovery.pcap) so the test resources directory contains no opaque blobs.
        PcapSniffer sniffer = new PcapSniffer("arp");
        Path syntheticPcap = tmp.resolve("synthetic-arp.pcap");
        Files.write(syntheticPcap, buildArpRequestPcap());

        List<DiscoveredNeighbor> neighbors = sniffer.replay(syntheticPcap.toFile());
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

    /**
     * Builds a complete pcap-format byte array with one Ethernet+ARP-request record.
     * Sender = {@code aa:bb:cc:dd:ee:ff @ 192.168.1.1}; target = {@code 00:00:00:00:00:00 @ 192.168.1.99}.
     * Avoids committing any binary fixture; the bytes here are pure RFC-pcap and RFC-826 fields.
     */
    private byte[] buildArpRequestPcap() {
        // Ethernet header (14 bytes) + ARP packet (28 bytes) = 42-byte frame
        ByteBuffer eth = ByteBuffer.allocate(42).order(ByteOrder.BIG_ENDIAN);
        // Ethernet: dst broadcast, src aa:bb:cc:dd:ee:ff, ethertype 0x0806 (ARP)
        eth.put(new byte[] {(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff});
        eth.put(new byte[] {(byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff});
        eth.putShort((short) 0x0806);
        // ARP: htype=1 (eth), ptype=0x0800 (IPv4), hlen=6, plen=4, oper=1 (request)
        eth.putShort((short) 1);
        eth.putShort((short) 0x0800);
        eth.put((byte) 6);
        eth.put((byte) 4);
        eth.putShort((short) 1);
        // sender MAC + IP: aa:bb:cc:dd:ee:ff @ 192.168.1.1
        eth.put(new byte[] {(byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff});
        eth.put(new byte[] {(byte)192, (byte)168, (byte)1, (byte)1});
        // target MAC + IP: 00:00:00:00:00:00 @ 192.168.1.99
        eth.put(new byte[] {0, 0, 0, 0, 0, 0});
        eth.put(new byte[] {(byte)192, (byte)168, (byte)1, (byte)99});
        byte[] frame = eth.array();

        // pcap record header (16 bytes, little-endian) + frame
        ByteBuffer rec = ByteBuffer.allocate(16 + frame.length).order(ByteOrder.LITTLE_ENDIAN);
        rec.putInt(0);                  // ts_sec
        rec.putInt(0);                  // ts_usec
        rec.putInt(frame.length);       // incl_len
        rec.putInt(frame.length);       // orig_len
        rec.put(frame);

        byte[] global = buildPcapGlobalHeader();
        byte[] out = new byte[global.length + rec.array().length];
        System.arraycopy(global, 0, out, 0, global.length);
        System.arraycopy(rec.array(), 0, out, global.length, rec.array().length);
        return out;
    }
}
