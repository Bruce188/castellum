package io.castellum.discovery;

import java.time.Duration;
import java.util.stream.Stream;

/**
 * Abstraction that unifies live (pcap4j {@code Pcaps.openLive}) and replay
 * ({@code Pcaps.openOffline}) capture paths.
 *
 * <p>Implementations must close their pcap handle before returning, even on
 * exception. Live implementations enforce the duration via a
 * {@code ScheduledExecutorService} that calls {@code pcapHandle.breakLoop()}.
 */
public interface PacketCaptureSource {

    /**
     * Capture inbound frames for at most {@code boundedDuration}, decode them,
     * and return a stream of {@link Discovery} records.
     *
     * @param boundedDuration maximum time to capture
     * @return stream of decoded discoveries (may be empty)
     * @throws DiscoveryUnavailableException if the underlying capture device
     *         cannot be opened (missing capabilities, missing libpcap, etc.)
     */
    Stream<Discovery> capture(Duration boundedDuration);
}
