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
 * Live DHCP frame capture on a named interface, bounded by duration and a frame cap.
 *
 * <p>Mirrors {@link CdpCapture}: each raw frame is delegated to
 * {@link DhcpDecoder#decode(byte[], String)} via {@code CaptureLoop.captureAndDecode}.
 * The capture buffer is bounded by {@code castellum.discovery.dhcp.max-captured-frames}
 * (default 1000). The live loop is not unit-tested (needs {@code CAP_NET_RAW}); the
 * decoder is the tested unit and service-level dispatch is tested with a mocked
 * DhcpCapture.
 */
@Service
public class DhcpCapture {

    private static final Logger log = LoggerFactory.getLogger(DhcpCapture.class);

    /** Port-pair match, repeated under {@code vlan} so single-tagged frames also pass. */
    private static final String DHCP_BPF_FILTER =
        "(udp and (port 67 or port 68)) or (vlan and udp and (port 67 or port 68))";

    private static final String CAP_WARN_MESSAGE =
        "DHCP frame cap reached — further frames in this window dropped (cap={})";

    private final DhcpDecoder dhcpDecoder;
    private final int maxCapturedFrames;

    public DhcpCapture(
            DhcpDecoder dhcpDecoder,
            @Value("${castellum.discovery.dhcp.max-captured-frames:1000}") int maxCapturedFrames) {
        this.dhcpDecoder = dhcpDecoder;
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
        return CaptureLoop.captureAndDecode(iface, durationSeconds, DHCP_BPF_FILTER,
            PromiscuousMode.PROMISCUOUS, maxCapturedFrames, log, CAP_WARN_MESSAGE,
            "DHCP", dhcpDecoder::decode);
    }
}
