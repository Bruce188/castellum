package io.castellum.discovery;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * pcap4j wrapper for passive packet capture.
 *
 * <p>Opens a handle in non-promiscuous read-only mode with the configured BPF filter.
 * Live capture uses a virtual thread to call {@code breakLoop()} after the bounded duration.
 * Replay mode ({@link #replay(File)}) uses {@code Pcaps.openOffline} — no {@code CAP_NET_RAW} required.
 *
 * <p>The capture buffer is bounded by {@code castellum.discovery.pcap.max-captured-neighbors}:
 * once the cap is reached, further decoded neighbors in the window are dropped (the broad
 * {@code ip or ip6 or arp} filter would otherwise let a flooded link grow the queue without limit).
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
    private final int maxCapturedNeighbors;

    public PcapSniffer(
            @Value("${castellum.discovery.bpf-filter:arp}") String bpfFilter,
            @Value("${castellum.discovery.pcap.max-captured-neighbors:50000}") int maxCapturedNeighbors) {
        this.bpfFilter = bpfFilter;
        this.maxCapturedNeighbors = maxCapturedNeighbors;
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
        var captured = new AtomicInteger();

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

            handle.loop(-1, (Packet packet) -> decode(packet, iface, queue, captured));

            breakThread.interrupt();
        }

        return new ArrayList<>(queue);
    }

    /**
     * Offline replay from a pcap file. Does not require {@code CAP_NET_RAW}.
     */
    public List<DiscoveredNeighbor> replay(File pcapFile) throws PcapNativeException, NotOpenException, InterruptedException {
        var queue = new ConcurrentLinkedQueue<DiscoveredNeighbor>();
        var captured = new AtomicInteger();

        try (PcapHandle handle = Pcaps.openOffline(pcapFile.getAbsolutePath())) {
            handle.loop(-1, (Packet packet) -> decode(packet, pcapFile.getName(), queue, captured));
        }

        return new ArrayList<>(queue);
    }

    private void decode(Packet packet, String iface, ConcurrentLinkedQueue<DiscoveredNeighbor> queue, AtomicInteger captured) {
        if (packet == null) return;

        ArpPacket arp = packet.get(ArpPacket.class);
        if (arp != null) {
            decodeArp(arp, iface, queue, captured);
            return; // ARP frames carry no IP payload — fully handled above
        }

        IpV4Packet ipv4 = packet.get(IpV4Packet.class);
        if (ipv4 != null && ipv4.getHeader() != null) {
            offerIpNeighbor(ipv4.getHeader().getSrcAddr(), iface, queue, captured);
            offerIpNeighbor(ipv4.getHeader().getDstAddr(), iface, queue, captured);
            return;
        }

        IpV6Packet ipv6 = packet.get(IpV6Packet.class);
        if (ipv6 != null && ipv6.getHeader() != null) {
            offerIpNeighbor(ipv6.getHeader().getSrcAddr(), iface, queue, captured);
            offerIpNeighbor(ipv6.getHeader().getDstAddr(), iface, queue, captured);
        }
    }

    private void decodeArp(ArpPacket arp, String iface, ConcurrentLinkedQueue<DiscoveredNeighbor> queue, AtomicInteger captured) {
        var header = arp.getHeader();
        if (header == null) return;

        String ip  = header.getSrcProtocolAddr() != null
            ? header.getSrcProtocolAddr().getHostAddress() : null;
        String mac = header.getSrcHardwareAddr() != null
            ? header.getSrcHardwareAddr().toString() : null;

        if (ip == null || ip.isBlank()) return;
        if (!reserveCaptureSlot(captured)) return;

        queue.offer(new DiscoveredNeighbor(ip, mac, null, null, iface, null));
        log.debug("PCAP ARP decoded: {} -> {}", ip, mac);
    }

    /**
     * Emits a MAC-less neighbor for one IP-layer address. The frame's ethernet MAC is
     * deliberately NOT attached: for routed traffic it is the local gateway's NIC, and
     * {@link PassiveDiscoveryService} dedupes MAC-primary — attaching it would collapse
     * every off-network peer into a single bogus device.
     */
    private void offerIpNeighbor(InetAddress addr, String iface, ConcurrentLinkedQueue<DiscoveredNeighbor> queue, AtomicInteger captured) {
        if (!isHostAddress(addr)) return;
        if (!reserveCaptureSlot(captured)) return;
        String ip = addr.getHostAddress();
        queue.offer(new DiscoveredNeighbor(ip, null, null, null, iface, null));
        log.debug("PCAP IP decoded: {}", ip);
    }

    /**
     * Reserves one slot in the bounded capture buffer; the counter is kept separately because
     * {@link ConcurrentLinkedQueue#size()} is O(n). Once the cap is exceeded the first rejected
     * offer logs a single WARN and all further neighbors in the window are dropped.
     */
    private boolean reserveCaptureSlot(AtomicInteger captured) {
        int n = captured.incrementAndGet();
        if (n <= maxCapturedNeighbors) return true;
        if (n == maxCapturedNeighbors + 1) {
            log.warn("capture buffer cap reached — further neighbors in this window dropped (cap={})", maxCapturedNeighbors);
        }
        return false;
    }

    /**
     * Rejects non-host addresses: unspecified (0.0.0.0 / ::), limited broadcast
     * (255.255.255.255), subnet-directed broadcast (IPv4 last octet 255) and multicast
     * (224.0.0.0/4 / ff00::/8). Loopback and link-local pass through —
     * {@link DiscoveryScopeClassifier} labels those downstream.
     */
    private static boolean isHostAddress(InetAddress addr) {
        if (addr == null) return false;
        String ip = addr.getHostAddress();
        if (ip == null || ip.isBlank()) return false;
        if (addr.isAnyLocalAddress() || addr.isMulticastAddress()) return false;
        // Last-octet-255 heuristic: drops NetBIOS/SSDP directed-broadcast noise at the cost
        // of a legitimate x.x.x.255 host on a /23-or-wider subnet.
        if (addr instanceof Inet4Address && (addr.getAddress()[3] & 0xFF) == 255) return false;
        return !"255.255.255.255".equals(ip);
    }
}
