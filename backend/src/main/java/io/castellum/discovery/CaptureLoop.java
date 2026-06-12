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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Shared live-capture scaffold for the pcap4j-based collectors ({@link PcapSniffer},
 * {@link LldpCapture}): resolve the interface, open a live handle, apply a BPF filter,
 * bound the loop with a virtual break thread, and hand each packet to the caller.
 *
 * <p>Callers keep their own decode logic, promiscuity mode, filter expression and
 * capture cap — only the open/filter/break/loop plumbing lives here.
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
