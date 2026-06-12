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
 * Live LLDP frame capture on a named interface, bounded by duration and a frame cap.
 *
 * <p>Mirrors {@link PcapSniffer#sniff(String, int)} but opens the handle in promiscuous
 * mode (LLDP frames go to multicast {@code 01:80:c2:00:00:0e} and may not be delivered to
 * a non-promiscuous handle) with the BPF filter {@code ether proto 0x88cc}, delegating
 * each raw frame to {@link LldpDecoder#decode(byte[], String)} via
 * {@link CaptureLoop#captureAndDecode}.
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

    private static final String CAP_WARN_MESSAGE =
        "LLDP frame cap reached — further frames in this window dropped (cap={})";

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
        return CaptureLoop.captureAndDecode(iface, durationSeconds, LLDP_BPF_FILTER,
            PromiscuousMode.PROMISCUOUS, maxCapturedFrames, log, CAP_WARN_MESSAGE,
            "LLDP", lldpDecoder::decode);
    }
}
