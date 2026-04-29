package io.castellum.discovery;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * pcap4j wrapper for passive packet capture.
 *
 * <p>Opens a handle in non-promiscuous read-only mode with the configured BPF filter.
 * Live capture uses a virtual thread to call {@code breakLoop()} after the bounded duration.
 * Replay mode ({@link #replay(File)}) uses {@code Pcaps.openOffline} — no {@code CAP_NET_RAW} required.
 *
 * <p>If {@code PcapNetworkInterface.openLive} throws {@link PcapNativeException} (missing libpcap,
 * missing {@code CAP_NET_RAW}), the exception propagates to the orchestrator for wrapping in
 * {@link DiscoveryUnavailableException}.
 */
@Service
public class PcapSniffer {

    private static final Logger log = LoggerFactory.getLogger(PcapSniffer.class);

    private static final int SNAP_LEN = 65536;
    private static final int TIMEOUT_MS = 10;

    private final String bpfFilter;

    public PcapSniffer(@Value("${castellum.discovery.bpf-filter:arp}") String bpfFilter) {
        this.bpfFilter = bpfFilter;
    }

    /**
     * Live capture on the named interface for the given duration.
     * Requires {@code CAP_NET_RAW} and {@code libpcap.so}.
     *
     * @throws PcapNativeException if the interface cannot be opened
     * @throws NotOpenException    if the handle is closed unexpectedly
     */
    public List<DiscoveredNeighbor> sniff(String iface, int durationSeconds) throws PcapNativeException, NotOpenException, InterruptedException {
        PcapNetworkInterface nif = Pcaps.getDevByName(iface);
        if (nif == null) {
            throw new PcapNativeException("Network interface not found: " + iface);
        }

        var queue = new ConcurrentLinkedQueue<DiscoveredNeighbor>();

        try (PcapHandle handle = nif.openLive(SNAP_LEN, PromiscuousMode.NONPROMISCUOUS, TIMEOUT_MS)) {
            handle.setFilter(bpfFilter, BpfCompileMode.OPTIMIZE);

            // Virtual thread to enforce the bounded duration
            Thread breakThread = Thread.ofVirtual().start(() -> {
                try {
                    Thread.sleep(Duration.ofSeconds(durationSeconds).toMillis());
                    try {
                        handle.breakLoop();
                    } catch (NotOpenException ignored) {
                        // Handle already closed — normal during shutdown
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });

            handle.loop(-1, (Packet packet) -> decode(packet, iface, queue));

            breakThread.interrupt();
        }

        return new ArrayList<>(queue);
    }

    /**
     * Offline replay from a pcap file. Does not require {@code CAP_NET_RAW}.
     */
    public List<DiscoveredNeighbor> replay(File pcapFile) throws PcapNativeException, NotOpenException, InterruptedException {
        var queue = new ConcurrentLinkedQueue<DiscoveredNeighbor>();

        try (PcapHandle handle = Pcaps.openOffline(pcapFile.getAbsolutePath())) {
            handle.loop(-1, (Packet packet) -> decode(packet, pcapFile.getName(), queue));
        }

        return new ArrayList<>(queue);
    }

    private void decode(Packet packet, String iface, ConcurrentLinkedQueue<DiscoveredNeighbor> queue) {
        if (packet == null) return;
        ArpPacket arp = packet.get(ArpPacket.class);
        if (arp == null) return;

        var header = arp.getHeader();
        if (header == null) return;

        String ip  = header.getSrcProtocolAddr() != null
            ? header.getSrcProtocolAddr().getHostAddress() : null;
        String mac = header.getSrcHardwareAddr() != null
            ? header.getSrcHardwareAddr().toString() : null;

        if (ip == null || ip.isBlank()) return;

        queue.offer(new DiscoveredNeighbor(ip, mac, null, null, iface));
        log.debug("PCAP ARP decoded: {} -> {}", ip, mac);
    }
}
