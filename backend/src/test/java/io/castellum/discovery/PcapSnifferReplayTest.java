package io.castellum.discovery;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.pcap4j.core.PcapNativeException;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PcapSnifferReplayTest {

    /** Mirrors the annotation default of castellum.discovery.pcap.max-captured-neighbors. */
    private static final int DEFAULT_CAP = 50_000;

    @Test
    void replay_arpFixture_decodesArpRequests_returnsNeighbors(@TempDir Path tmp) throws Exception {
        // Synthetic single-record pcap built at runtime — replaces the prior committed binary
        // fixture (arp-self-discovery.pcap) so the test resources directory contains no opaque blobs.
        PcapSniffer sniffer = new PcapSniffer("arp", DEFAULT_CAP);
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
    void replay_arpFixture_emitsExactlyOneNeighborWithMac(@TempDir Path tmp) throws Exception {
        // Regression guard for the IP-decoding extension: an ARP frame must still yield the
        // single sender-side neighbor and nothing else (ARP frames carry no IP payload).
        PcapSniffer sniffer = new PcapSniffer("arp", DEFAULT_CAP);
        Path syntheticPcap = tmp.resolve("synthetic-arp.pcap");
        Files.write(syntheticPcap, buildArpRequestPcap());

        List<DiscoveredNeighbor> neighbors = sniffer.replay(syntheticPcap.toFile());
        assertThat(neighbors).hasSize(1);
        DiscoveredNeighbor n = neighbors.get(0);
        assertThat(n.ipAddress()).isEqualTo("192.168.1.1");
        assertThat(n.macAddress()).isEqualTo("aa:bb:cc:dd:ee:ff");
        assertThat(n.iface()).isEqualTo("synthetic-arp.pcap");
    }

    @Test
    void replay_ipv4Tcp_emitsSrcAndDstNeighbors_withNullMac(@TempDir Path tmp) throws Exception {
        PcapSniffer sniffer = new PcapSniffer("arp", DEFAULT_CAP);
        Path pcap = tmp.resolve("ipv4-tcp.pcap");
        Files.write(pcap, buildIpV4TcpPcap("192.168.1.50", "203.0.113.7"));

        List<DiscoveredNeighbor> neighbors = sniffer.replay(pcap.toFile());
        assertThat(neighbors).hasSize(2);
        assertThat(neighbors).extracting(DiscoveredNeighbor::ipAddress)
            .containsExactlyInAnyOrder("192.168.1.50", "203.0.113.7");
        // MAC must stay null: the frame's ethernet MAC is the gateway NIC for routed
        // traffic, and the MAC-primary dedupe would merge all peers into one device.
        assertThat(neighbors).allSatisfy(n -> {
            assertThat(n.macAddress()).isNull();
            assertThat(n.iface()).isEqualTo("ipv4-tcp.pcap");
        });
    }

    @Test
    void replay_ipv4Tcp_multicastDst_emitsOnlySrc(@TempDir Path tmp) throws Exception {
        PcapSniffer sniffer = new PcapSniffer("arp", DEFAULT_CAP);
        Path pcap = tmp.resolve("ipv4-mcast.pcap");
        Files.write(pcap, buildIpV4TcpPcap("192.168.1.50", "239.255.255.250"));

        List<DiscoveredNeighbor> neighbors = sniffer.replay(pcap.toFile());
        assertThat(neighbors).extracting(DiscoveredNeighbor::ipAddress)
            .containsExactly("192.168.1.50");
    }

    @Test
    void replay_ipv4Tcp_broadcastDst_emitsOnlySrc(@TempDir Path tmp) throws Exception {
        PcapSniffer sniffer = new PcapSniffer("arp", DEFAULT_CAP);
        Path pcap = tmp.resolve("ipv4-bcast.pcap");
        Files.write(pcap, buildIpV4TcpPcap("192.168.1.50", "255.255.255.255"));

        List<DiscoveredNeighbor> neighbors = sniffer.replay(pcap.toFile());
        assertThat(neighbors).extracting(DiscoveredNeighbor::ipAddress)
            .containsExactly("192.168.1.50");
    }

    @Test
    void replay_ipv4Tcp_directedBroadcastDst_emitsOnlySrc(@TempDir Path tmp) throws Exception {
        // 192.168.1.255-style subnet-directed broadcast (NetBIOS/SSDP noise) must not
        // become a phantom device; the unicast src must still come through.
        PcapSniffer sniffer = new PcapSniffer("arp", DEFAULT_CAP);
        Path pcap = tmp.resolve("ipv4-directed-bcast.pcap");
        Files.write(pcap, buildIpV4TcpPcap("192.168.1.50", "192.168.1.255"));

        List<DiscoveredNeighbor> neighbors = sniffer.replay(pcap.toFile());
        assertThat(neighbors).extracting(DiscoveredNeighbor::ipAddress)
            .containsExactly("192.168.1.50");
    }

    @Test
    void replay_moreHostsThanCap_truncatesAtCap_withoutThrowing(@TempDir Path tmp) throws Exception {
        // Cap of 3 against 3 packets carrying 6 distinct host addresses: the buffer must
        // stop growing at the cap and the replay must still complete normally.
        PcapSniffer sniffer = new PcapSniffer("arp", 3);
        Path pcap = tmp.resolve("ipv4-flood.pcap");
        Files.write(pcap, wrapFrames(
            buildIpV4TcpFrame("10.0.0.1", "10.0.0.2"),
            buildIpV4TcpFrame("10.0.0.3", "10.0.0.4"),
            buildIpV4TcpFrame("10.0.0.5", "10.0.0.6")));

        List<DiscoveredNeighbor> neighbors = sniffer.replay(pcap.toFile());
        assertThat(neighbors).hasSize(3);
        // Offline replay is single-threaded, so truncation keeps arrival order
        assertThat(neighbors).extracting(DiscoveredNeighbor::ipAddress)
            .containsExactly("10.0.0.1", "10.0.0.2", "10.0.0.3");
    }

    @Test
    void replay_ipv4Tcp_unspecifiedSrcAndBroadcastDst_emitsNothing(@TempDir Path tmp) throws Exception {
        // DHCP-DISCOVER shape: 0.0.0.0 -> 255.255.255.255 carries no host address at all
        PcapSniffer sniffer = new PcapSniffer("arp", DEFAULT_CAP);
        Path pcap = tmp.resolve("ipv4-dhcp.pcap");
        Files.write(pcap, buildIpV4TcpPcap("0.0.0.0", "255.255.255.255"));

        assertThat(sniffer.replay(pcap.toFile())).isEmpty();
    }

    @Test
    void replay_ipv6Udp_emitsSrcAndDstNeighbors_withNullMac(@TempDir Path tmp) throws Exception {
        PcapSniffer sniffer = new PcapSniffer("arp", DEFAULT_CAP);
        Path pcap = tmp.resolve("ipv6-udp.pcap");
        Files.write(pcap, buildIpV6UdpPcap("2001:db8::1", "2606:4700::6810:84e5"));

        List<DiscoveredNeighbor> neighbors = sniffer.replay(pcap.toFile());
        assertThat(neighbors).hasSize(2);
        assertThat(neighbors).extracting(DiscoveredNeighbor::ipAddress)
            .containsExactlyInAnyOrder(
                InetAddress.getByName("2001:db8::1").getHostAddress(),
                InetAddress.getByName("2606:4700::6810:84e5").getHostAddress());
        assertThat(neighbors).allSatisfy(n -> assertThat(n.macAddress()).isNull());
    }

    @Test
    void replay_ipv6Udp_multicastDst_emitsOnlySrc(@TempDir Path tmp) throws Exception {
        PcapSniffer sniffer = new PcapSniffer("arp", DEFAULT_CAP);
        Path pcap = tmp.resolve("ipv6-mcast.pcap");
        Files.write(pcap, buildIpV6UdpPcap("fe80::1", "ff02::fb"));

        List<DiscoveredNeighbor> neighbors = sniffer.replay(pcap.toFile());
        // fe80:: link-local is NOT filtered here — DiscoveryScopeClassifier labels it downstream
        assertThat(neighbors).extracting(DiscoveredNeighbor::ipAddress)
            .containsExactly(InetAddress.getByName("fe80::1").getHostAddress());
    }

    @Test
    void replay_emptyPcap_returnsEmptyList(@TempDir Path tmp) throws Exception {
        // Create a minimal pcap with header but zero records
        Path emptyPcap = tmp.resolve("empty.pcap");
        byte[] globalHdr = buildPcapGlobalHeader();
        Files.write(emptyPcap, globalHdr);

        PcapSniffer sniffer = new PcapSniffer("arp", DEFAULT_CAP);
        List<DiscoveredNeighbor> neighbors = sniffer.replay(emptyPcap.toFile());
        assertThat(neighbors).isEmpty();
    }

    @Test
    void live_handle_close_inFinally() {
        PcapSniffer sniffer = new PcapSniffer("arp", DEFAULT_CAP);
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
        return wrapFrame(eth.array());
    }

    /**
     * Builds a complete pcap-format byte array with one Ethernet+IPv4+TCP record.
     * Checksums are zero — pcap4j does not verify them at parse time. The ethernet
     * MACs are locally-administered throwaways; decode must never propagate them.
     */
    private byte[] buildIpV4TcpPcap(String srcIp, String dstIp) throws Exception {
        return wrapFrame(buildIpV4TcpFrame(srcIp, dstIp));
    }

    /** Builds one raw Ethernet+IPv4+TCP frame (no pcap headers) for multi-record fixtures. */
    private byte[] buildIpV4TcpFrame(String srcIp, String dstIp) throws Exception {
        // Ethernet header (14) + IPv4 header (20) + TCP header (20) = 54-byte frame
        ByteBuffer eth = ByteBuffer.allocate(54).order(ByteOrder.BIG_ENDIAN);
        // Ethernet: dst 02:00:00:00:00:02, src 02:00:00:00:00:01, ethertype 0x0800 (IPv4)
        eth.put(new byte[] {(byte)0x02, 0, 0, 0, 0, (byte)0x02});
        eth.put(new byte[] {(byte)0x02, 0, 0, 0, 0, (byte)0x01});
        eth.putShort((short) 0x0800);
        // IPv4: version 4, IHL 5, total length 40, DF, TTL 64, protocol 6 (TCP)
        eth.put((byte) 0x45);
        eth.put((byte) 0x00);
        eth.putShort((short) 40);
        eth.putShort((short) 0x1234);   // identification
        eth.putShort((short) 0x4000);   // flags: DF
        eth.put((byte) 64);
        eth.put((byte) 6);
        eth.putShort((short) 0);        // checksum (unverified)
        eth.put(InetAddress.getByName(srcIp).getAddress());
        eth.put(InetAddress.getByName(dstIp).getAddress());
        // TCP: SYN, data offset 5, no options
        eth.putShort((short) 12345);
        eth.putShort((short) 443);
        eth.putInt(0);                  // seq
        eth.putInt(0);                  // ack
        eth.put((byte) 0x50);           // data offset 5
        eth.put((byte) 0x02);           // SYN
        eth.putShort((short) 0xffff);   // window
        eth.putShort((short) 0);        // checksum (unverified)
        eth.putShort((short) 0);        // urgent pointer
        return eth.array();
    }

    /**
     * Builds a complete pcap-format byte array with one Ethernet+IPv6+UDP record.
     */
    private byte[] buildIpV6UdpPcap(String srcIp, String dstIp) throws Exception {
        // Ethernet header (14) + IPv6 header (40) + UDP header (8) = 62-byte frame
        ByteBuffer eth = ByteBuffer.allocate(62).order(ByteOrder.BIG_ENDIAN);
        // Ethernet: dst 02:00:00:00:00:02, src 02:00:00:00:00:01, ethertype 0x86dd (IPv6)
        eth.put(new byte[] {(byte)0x02, 0, 0, 0, 0, (byte)0x02});
        eth.put(new byte[] {(byte)0x02, 0, 0, 0, 0, (byte)0x01});
        eth.putShort((short) 0x86dd);
        // IPv6: version 6, traffic class 0, flow label 0, payload length 8, next header 17 (UDP)
        eth.putInt(0x60000000);
        eth.putShort((short) 8);
        eth.put((byte) 17);
        eth.put((byte) 64);             // hop limit
        eth.put(InetAddress.getByName(srcIp).getAddress());
        eth.put(InetAddress.getByName(dstIp).getAddress());
        // UDP: length 8 (header only), checksum 0 (unverified)
        eth.putShort((short) 40000);
        eth.putShort((short) 53);
        eth.putShort((short) 8);
        eth.putShort((short) 0);
        return wrapFrame(eth.array());
    }

    /** Wraps a single ethernet frame in a pcap global header + one record header. */
    private byte[] wrapFrame(byte[] frame) {
        return wrapFrames(frame);
    }

    /** Wraps ethernet frames in a pcap global header, one record header per frame. */
    private byte[] wrapFrames(byte[]... frames) {
        byte[] global = buildPcapGlobalHeader();
        int total = global.length;
        for (byte[] frame : frames) {
            total += 16 + frame.length;
        }

        ByteBuffer out = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
        out.put(global);
        for (byte[] frame : frames) {
            // pcap record header (16 bytes, little-endian) + frame
            out.putInt(0);              // ts_sec
            out.putInt(0);              // ts_usec
            out.putInt(frame.length);   // incl_len
            out.putInt(frame.length);   // orig_len
            out.put(frame);
        }
        return out.array();
    }
}
