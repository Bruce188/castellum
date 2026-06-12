package io.castellum.discovery;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;
import java.util.function.Consumer;

/**
 * Shared live-capture scaffold for the pcap4j-based collectors ({@link PcapSniffer},
 * {@link LldpCapture}, {@link CdpCapture}): resolve the interface, open a live handle,
 * apply a BPF filter, bound the loop with a virtual break thread, and hand each packet
 * to the caller.
 *
 * <p>Callers keep their own decode logic, promiscuity mode, filter expression and
 * capture cap — only the open/filter/break/loop plumbing lives here. Frame-decoding
 * collectors (LLDP/CDP) additionally share {@link #captureAndDecode}, which buffers raw
 * frames during the loop and defers all decode work until the loop ends.
 */
final class CaptureLoop {

    private static final int SNAP_LEN = 65536;
    private static final int TIMEOUT_MS = 10;

    private CaptureLoop() {
        throw new UnsupportedOperationException("static utility");
    }

    /**
     * Runs a bounded live capture on the named interface, invoking
     * {@code perPacketConsumer} for every captured packet.
     *
     * @throws PcapNativeException if the interface cannot be found or opened
     * @throws NotOpenException    if the handle is closed unexpectedly
     */
    static void run(String iface, int durationSeconds, String bpfFilter,
                    PromiscuousMode promiscuousMode, Consumer<Packet> perPacketConsumer)
            throws PcapNativeException, NotOpenException, InterruptedException {
        PcapNetworkInterface nif = Pcaps.getDevByName(iface);
        if (nif == null) {
            throw new PcapNativeException("Network interface not found: " + iface);
        }

        try (PcapHandle handle = nif.openLive(SNAP_LEN, promiscuousMode, TIMEOUT_MS)) {
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

            handle.loop(-1, (Packet packet) -> perPacketConsumer.accept(packet));

            breakThread.interrupt();
        }
    }

    /**
     * Runs a bounded live capture and decodes every captured frame into
     * {@link DiscoveredNeighbor}s via the supplied {@code (rawFrame, iface)} decoder.
     *
     * <p>The pcap callback only buffers the raw frame bytes (capped at {@code maxFrames};
     * frames beyond the cap are dropped, the first logging a single WARN through the
     * caller's logger and {@code capWarnMessage} — which must contain one {@code {}}
     * placeholder for the cap). Decoding, address conversion and per-neighbor debug
     * logging all run after the loop ends, so no decode work back-pressures the capture
     * callback thread.
     *
     * @throws PcapNativeException if the interface cannot be found or opened
     * @throws NotOpenException    if the handle is closed unexpectedly
     */
    static List<DiscoveredNeighbor> captureAndDecode(
            String iface, int durationSeconds, String bpfFilter, PromiscuousMode promiscuousMode,
            int maxFrames, Logger log, String capWarnMessage, String sourceLabel,
            BiFunction<byte[], String, List<DiscoveredNeighbor>> decoder)
            throws PcapNativeException, NotOpenException, InterruptedException {
        var frames = new ConcurrentLinkedQueue<byte[]>();
        var captured = new AtomicInteger();

        run(iface, durationSeconds, bpfFilter, promiscuousMode, packet -> {
            if (packet == null) {
                return;
            }
            byte[] raw = packet.getRawData();
            if (raw == null) {
                return;
            }
            if (!reserveCaptureSlot(captured, maxFrames, log, capWarnMessage)) {
                return;
            }
            frames.offer(raw);
        });

        List<DiscoveredNeighbor> neighbors = new ArrayList<>();
        for (byte[] raw : frames) {
            for (DiscoveredNeighbor n : decoder.apply(raw, iface)) {
                neighbors.add(n);
                log.debug("{} decoded: ip={} mac={} hostname={}",
                    sourceLabel, n.ipAddress(), n.macAddress(), n.hostname());
            }
        }
        return neighbors;
    }

    /**
     * Reserves one slot in a bounded capture buffer; the counter is kept separately because
     * {@code ConcurrentLinkedQueue#size()} is O(n). Once the cap is exceeded the first
     * rejected offer logs a single WARN (via the caller's logger and message, which must
     * contain a single {@code {}} placeholder for the cap) and all further entries in the
     * window are dropped.
     */
    static boolean reserveCaptureSlot(AtomicInteger captured, int cap, Logger log, String warnMessage) {
        int n = captured.incrementAndGet();
        if (n <= cap) {
            return true;
        }
        if (n == cap + 1) {
            log.warn(warnMessage, cap);
        }
        return false;
    }
}
