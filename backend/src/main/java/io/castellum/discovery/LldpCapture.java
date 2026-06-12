package io.castellum.discovery;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Live LLDP frame capture on a named interface, bounded by duration and a frame cap.
 *
 * <p>Mirrors {@link PcapSniffer#sniff(String, int)} but opens the handle in promiscuous
 * mode (LLDP frames go to multicast {@code 01:80:c2:00:00:0e} and may not be delivered to
 * a non-promiscuous handle) with the BPF filter {@code ether proto 0x88cc}, delegating
 * each raw frame to {@link LldpDecoder#decode(byte[], String)}.
 *
 * <p>The capture buffer is bounded by {@code castellum.discovery.lldp.max-captured-frames}
 * (default 1000), using the same reserve-slot pattern as PcapSniffer. The live loop is not
 * unit-tested (needs {@code CAP_NET_RAW}); the decoder is the tested unit and service-level
 * dispatch is tested with a mocked LldpCapture.
 */
@Service
public class LldpCapture {

    private static final Logger log = LoggerFactory.getLogger(LldpCapture.class);

    private static final String LLDP_BPF_FILTER = "ether proto 0x88cc";

    private final LldpDecoder lldpDecoder;
    private final int maxCapturedFrames;

    public LldpCapture(
            LldpDecoder lldpDecoder,
            @Value("${castellum.discovery.lldp.max-captured-frames:1000}") int maxCapturedFrames) {
        this.lldpDecoder = lldpDecoder;
        this.maxCapturedFrames = maxCapturedFrames;
    }

    /**
     * Live capture on the named interface for the given duration.
     * Requires {@code CAP_NET_RAW} and {@code libpcap.so}.
     *
     * @throws PcapNativeException if the interface cannot be opened
     * @throws NotOpenException    if the handle is closed unexpectedly
     */
    public List<DiscoveredNeighbor> capture(String iface, int durationSeconds)
            throws PcapNativeException, NotOpenException, InterruptedException {
        var queue = new ConcurrentLinkedQueue<DiscoveredNeighbor>();
        var captured = new AtomicInteger();

        CaptureLoop.run(iface, durationSeconds, LLDP_BPF_FILTER, PromiscuousMode.PROMISCUOUS,
            packet -> decodeFrame(packet, iface, queue, captured));

        return new ArrayList<>(queue);
    }

    private void decodeFrame(Packet packet, String iface,
                             ConcurrentLinkedQueue<DiscoveredNeighbor> queue, AtomicInteger captured) {
        if (packet == null) {
            return;
        }
        byte[] raw = packet.getRawData();
        if (raw == null) {
            return;
        }
        if (!reserveCaptureSlot(captured)) {
            return;
        }
        for (DiscoveredNeighbor n : lldpDecoder.decode(raw, iface)) {
            queue.offer(n);
            log.debug("LLDP decoded: ip={} mac={} hostname={}", n.ipAddress(), n.macAddress(), n.hostname());
        }
    }

    /**
     * Reserves one slot in the bounded frame buffer; once the cap is exceeded the first
     * rejected frame logs a single WARN and all further frames in the window are dropped.
     */
    private boolean reserveCaptureSlot(AtomicInteger captured) {
        return CaptureLoop.reserveCaptureSlot(captured, maxCapturedFrames, log,
            "LLDP frame cap reached — further frames in this window dropped (cap={})");
    }
}
