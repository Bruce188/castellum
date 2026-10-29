package io.castellum.discovery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceListener;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * mDNS probe operating in <strong>listen-only</strong> mode.
 *
 * <p>Listen-only contract: do not call {@code JmDNS.list(...)} anywhere in this class.
 * Calling {@code list()} would emit unicast mDNS service queries — active probing, which
 * is explicitly out of scope for passive discovery. Use {@code addServiceListener} only.
 *
 * <p>It also adds an opt-in raw-datagram half
 * ({@code castellum.discovery.mdns.payload-decode.enabled}): a plain
 * {@link MulticastSocket} on 5353 (SO_REUSEADDR — coexists with JmDNS's own binding
 * in-process) buffers group datagrams during the same window, capped at
 * {@code castellum.discovery.mdns.max-captured-datagrams}, and hands them to
 * {@link MdnsPayloadDecoder} only after the window ends (decode-after-window
 * discipline). The raw socket only ever receives — listen-only intact. A socket open
 * failure soft-degrades to the JmDNS half with a WARN; it never turns the MDNS source
 * UNAVAILABLE.
 */
@Service
public class MdnsProbe {

    private static final Logger log = LoggerFactory.getLogger(MdnsProbe.class);

    private final List<String> serviceTypes;
    private final MdnsPayloadDecoder payloadDecoder;
    private final boolean payloadDecodeEnabled;
    private final int maxCapturedDatagrams;

    public MdnsProbe(
            @Value("${castellum.discovery.mdns.service-types:_workstation._tcp.local.,_http._tcp.local.,_ssh._tcp.local.,_smb._tcp.local.,_printer._tcp.local.}")
            String serviceTypesConfig,
            MdnsPayloadDecoder payloadDecoder,
            @Value("${castellum.discovery.mdns.payload-decode.enabled:false}") boolean payloadDecodeEnabled,
            @Value("${castellum.discovery.mdns.max-captured-datagrams:1000}") int maxCapturedDatagrams) {
        // Split comma-separated string from @Value
        this.serviceTypes = List.of(serviceTypesConfig.split(","));
        this.payloadDecoder = payloadDecoder;
        this.payloadDecodeEnabled = payloadDecodeEnabled;
        this.maxCapturedDatagrams = maxCapturedDatagrams;
    }

    /**
     * Listens for mDNS service announcements for the given duration and returns
     * the discovered neighbors.
     *
     * @param durationSeconds how long to listen (bounded duration)
     * @return list of discovered neighbors; empty if nothing was heard
     * @throws DiscoveryUnavailableException if multicast is unavailable
     */
    public List<DiscoveredNeighbor> probe(int durationSeconds) throws DiscoveryUnavailableException {
        Queue<DiscoveredNeighbor> queue = new ConcurrentLinkedQueue<>();

        ServiceListener listener = new ServiceListener() {
            @Override
            public void serviceAdded(ServiceEvent event) {
                // service added, waiting for resolve
            }

            @Override
            public void serviceRemoved(ServiceEvent event) {
                // not relevant for discovery
            }

            @Override
            public void serviceResolved(ServiceEvent event) {
                var info = event.getInfo();
                if (info == null) return;
                InetAddress[] addrs = info.getInet4Addresses();
                String firstIp = firstNonNull(addrs);
                DiscoveredNeighbor n = buildNeighbor(firstIp, info.getServer());
                if (n != null) {
                    queue.offer(n);
                    log.debug("mDNS resolved: name={} ip={} hostname={}",
                        info.getName(), n.ipAddress(), n.hostname());
                }
            }
        };

        // Raw payload half (opt-in): buffer group datagrams during the same window,
        // decode only after it ends. Open failure soft-degrades to the JmDNS half.
        MulticastSocket rawSocket = payloadDecodeEnabled ? openRawSocket() : null;
        Queue<byte[]> datagrams = new ConcurrentLinkedQueue<>();
        Thread receiveThread = rawSocket == null ? null : startReceiveLoop(rawSocket, datagrams);

        JmDNS jmdns = null;
        try {
            jmdns = JmDNS.create(InetAddress.getLocalHost());

            // Subscribe to meta-service and configured service types
            jmdns.addServiceListener("_services._dns-sd._udp.local.", listener);
            for (String type : serviceTypes) {
                String t = type.trim();
                if (!t.isEmpty()) {
                    jmdns.addServiceListener(t, listener);
                }
            }

            Thread.sleep(durationSeconds * 1000L);
        } catch (IOException e) {
            throw new DiscoveryUnavailableException("mDNS multicast unavailable: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("mDNS probe interrupted after partial duration");
        } finally {
            if (rawSocket != null) {
                rawSocket.close(); // unblocks the receive loop — its window is over
            }
            if (jmdns != null) {
                try {
                    jmdns.close();
                } catch (IOException e) {
                    log.warn("Error closing JmDNS: {}", e.getMessage());
                }
            }
        }

        List<DiscoveredNeighbor> results = new ArrayList<>(queue);
        if (payloadDecodeEnabled && receiveThread != null) {
            try {
                receiveThread.join(Duration.ofSeconds(1)); // let an in-flight offer land
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            for (byte[] datagram : datagrams) {
                results.addAll(payloadDecoder.decode(datagram));
            }
        }
        return results;
    }

    /**
     * Opens the raw 5353 multicast socket for the payload half, or null on failure —
     * the probe then runs on the JmDNS half alone (soft-degrade; a refused second
     * 5353 bind must not turn the MDNS source UNAVAILABLE). The
     * {@link MulticastSocket} constructor enables SO_REUSEADDR before binding.
     */
    private MulticastSocket openRawSocket() {
        try {
            MulticastSocket socket = new MulticastSocket(5353);
            socket.joinGroup(new InetSocketAddress(InetAddress.getByName("224.0.0.251"), 5353), null);
            return socket;
        } catch (IOException e) {
            log.warn("mDNS payload-decode socket unavailable — continuing with JmDNS only: {}",
                e.getMessage());
            return null;
        }
    }

    /**
     * Receives group datagrams on a virtual thread until the socket closes, buffering
     * raw copies for decode-after-window. The buffer is capped via the shared
     * single-WARN {@link CaptureLoop#reserveCaptureSlot} pattern.
     */
    private Thread startReceiveLoop(MulticastSocket socket, Queue<byte[]> datagrams) {
        AtomicInteger captured = new AtomicInteger();
        return Thread.ofVirtual().start(() -> {
            byte[] buffer = new byte[9000];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            while (!socket.isClosed()) {
                try {
                    socket.receive(packet);
                } catch (IOException e) {
                    break; // socket closed at the window end — normal termination
                }
                if (!CaptureLoop.reserveCaptureSlot(captured, maxCapturedDatagrams, log,
                        "mDNS datagram cap reached — further datagrams in this window dropped (cap={})")) {
                    continue;
                }
                datagrams.offer(Arrays.copyOf(packet.getData(), packet.getLength()));
            }
        });
    }

    /**
     * Builds a neighbor record from a resolved IPv4 address and mDNS server hostname.
     * Returns {@code null} when neither an IPv4 nor a hostname is available — the entry
     * carries no actionable information. Package-private for unit-test access.
     *
     * <p>Behavioral contract (Phase D.1):
     * <ul>
     *   <li>{@code ip != null} → emit {@code DiscoveredNeighbor(ip, null, null, null, null, hostname)}.</li>
     *   <li>{@code ip == null && hostname != null} → emit hostname-only neighbor with {@code ipAddress=null}
     *       (NOT the hostname stuffed into the ipAddress slot — that was the pre-D.1 bug).</li>
     *   <li>{@code ip == null && (hostname == null || blank)} → return null (skip).</li>
     * </ul>
     */
    static DiscoveredNeighbor buildNeighbor(String ip, String hostname) {
        if (ip == null) {
            if (hostname == null || hostname.isBlank()) return null;
            return new DiscoveredNeighbor(null, null, null, null, null, hostname, null);
        }
        return new DiscoveredNeighbor(ip, null, null, null, null, hostname, null);
    }

    private static String firstNonNull(InetAddress[] addrs) {
        if (addrs == null) return null;
        for (InetAddress a : addrs) {
            if (a != null) return a.getHostAddress();
        }
        return null;
    }
}
