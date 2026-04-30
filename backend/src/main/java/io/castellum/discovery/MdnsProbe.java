package io.castellum.discovery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceListener;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * mDNS probe operating in <strong>listen-only</strong> mode.
 *
 * <p>Listen-only contract: do not call {@code JmDNS.list(...)} anywhere in this class.
 * Calling {@code list()} would emit unicast mDNS service queries — active probing, which
 * is explicitly out of scope for passive discovery. Use {@code addServiceListener} only.
 */
@Service
public class MdnsProbe {

    private static final Logger log = LoggerFactory.getLogger(MdnsProbe.class);

    private final List<String> serviceTypes;

    public MdnsProbe(
            @Value("${castellum.discovery.mdns.service-types:_workstation._tcp.local.,_http._tcp.local.,_ssh._tcp.local.,_smb._tcp.local.,_printer._tcp.local.}")
            String serviceTypesConfig) {
        // Split comma-separated string from @Value
        this.serviceTypes = List.of(serviceTypesConfig.split(","));
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
            if (jmdns != null) {
                try {
                    jmdns.close();
                } catch (IOException e) {
                    log.warn("Error closing JmDNS: {}", e.getMessage());
                }
            }
        }

        return new ArrayList<>(queue);
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
            return new DiscoveredNeighbor(null, null, null, null, null, hostname);
        }
        return new DiscoveredNeighbor(ip, null, null, null, null, hostname);
    }

    private static String firstNonNull(InetAddress[] addrs) {
        if (addrs == null) return null;
        for (InetAddress a : addrs) {
            if (a != null) return a.getHostAddress();
        }
        return null;
    }
}
