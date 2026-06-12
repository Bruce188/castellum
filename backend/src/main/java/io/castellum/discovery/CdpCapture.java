package io.castellum.discovery;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Live CDP frame capture on a named interface, bounded by duration and a frame cap.
 *
 * <p>Mirrors {@link LldpCapture} but filters on the destination MAC: CDP rides 802.3/SNAP
 * frames, so there is no ethertype to match — {@code ether dst 01:00:0c:cc:cc:cc} is
 * 802.1Q-agnostic (an offset-based SNAP match would silently miss tagged frames the decoder
 * supports). The handle opens in promiscuous mode (multicast destination may never be
 * delivered to a non-promiscuous handle). The over-capture the filter admits (VTP/DTP/
 * PAgP/UDLD share the multicast group) is low-rate and discriminated by
 * {@link CdpDecoder}'s mandatory SNAP protocol-ID gate. Each raw frame is delegated to
 * {@link CdpDecoder#decode(byte[], String)} via {@link CaptureLoop#captureAndDecode}.
 *
 * <p>The capture buffer is bounded by {@code castellum.discovery.cdp.max-captured-frames}
 * (default 1000), using the same reserve-slot pattern as PcapSniffer. The live loop is not
 * unit-tested (needs {@code CAP_NET_RAW}); the decoder is the tested unit and service-level
 * dispatch is tested with a mocked CdpCapture.
 */
@Service
public class CdpCapture {

    private static final Logger log = LoggerFactory.getLogger(CdpCapture.class);

    private static final String CDP_BPF_FILTER = "ether dst 01:00:0c:cc:cc:cc";

    private static final String CAP_WARN_MESSAGE =
        "CDP frame cap reached — further frames in this window dropped (cap={})";

    private final CdpDecoder cdpDecoder;
    private final int maxCapturedFrames;

    public CdpCapture(
            CdpDecoder cdpDecoder,
            @Value("${castellum.discovery.cdp.max-captured-frames:1000}") int maxCapturedFrames) {
        this.cdpDecoder = cdpDecoder;
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
        return CaptureLoop.captureAndDecode(iface, durationSeconds, CDP_BPF_FILTER,
            PromiscuousMode.PROMISCUOUS, maxCapturedFrames, log, CAP_WARN_MESSAGE,
            "CDP", cdpDecoder::decode);
    }
}
