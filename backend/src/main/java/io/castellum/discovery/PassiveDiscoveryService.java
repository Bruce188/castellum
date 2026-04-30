package io.castellum.discovery;

import io.castellum.audit.AuditService;
import io.castellum.domain.Device;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/**
 * Orchestrates passive discovery by fanning out enabled sources on virtual threads,
 * collecting {@link DiscoveredNeighbor} records, deduplicating by IP address, and
 * upserting each into the {@link io.castellum.domain.Device} inventory via
 * {@link DeviceUpsertService}.
 *
 * <p>One {@code audit_log} row (action {@code PASSIVE_SWEEP}) is emitted per sweep.
 */
@Service
public class PassiveDiscoveryService {

    private static final Logger log = LoggerFactory.getLogger(PassiveDiscoveryService.class);

    private final ArpCacheReader arpReader;
    private final MdnsProbe mdnsProbe;
    private final PcapSniffer pcapSniffer;
    private final LldpDecoder lldpDecoder;
    private final CdpDecoder cdpDecoder;
    private final DeviceUpsertService upsertService;
    private final AuditService auditService;
    private final boolean lldpEnabled;
    private final boolean cdpEnabled;
    private final Clock clock;

    public PassiveDiscoveryService(
            ArpCacheReader arpReader,
            MdnsProbe mdnsProbe,
            PcapSniffer pcapSniffer,
            LldpDecoder lldpDecoder,
            CdpDecoder cdpDecoder,
            DeviceUpsertService upsertService,
            AuditService auditService,
            @Value("${castellum.discovery.lldp.enabled:false}") boolean lldpEnabled,
            @Value("${castellum.discovery.cdp.enabled:false}") boolean cdpEnabled,
            Clock clock) {
        this.arpReader = arpReader;
        this.mdnsProbe = mdnsProbe;
        this.pcapSniffer = pcapSniffer;
        this.lldpDecoder = lldpDecoder;
        this.cdpDecoder = cdpDecoder;
        this.upsertService = upsertService;
        this.auditService = auditService;
        this.lldpEnabled = lldpEnabled;
        this.cdpEnabled = cdpEnabled;
        this.clock = clock;
    }

    /**
     * Runs a bounded passive sweep and returns a summary of what was discovered.
     *
     * @throws DiscoveryUnavailableException if a required capability (CAP_NET_RAW, libpcap) is absent
     */
    public PassiveDiscoveryResponse sweep(PassiveDiscoveryRequest req) {
        // Validate PCAP-specific precondition
        if (req.sources().contains(DiscoverySource.PCAP)
                && (req.iface() == null || req.iface().isBlank())) {
            throw new DiscoveryUnavailableException("PCAP source requires interface name");
        }

        Map<DiscoverySource, Integer> perSourceCount = new EnumMap<>(DiscoverySource.class);
        for (DiscoverySource src : req.sources()) {
            perSourceCount.put(src, 0);
        }

        Map<String, Discovery> discoveredByIp = new LinkedHashMap<>();
        List<Future<List<DiscoveredNeighbor>>> futures = new ArrayList<>();
        List<DiscoverySource> submittedSources = new ArrayList<>();

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (DiscoverySource source : req.sources()) {
                switch (source) {
                    case ARP -> {
                        futures.add(executor.submit(() -> arpReader.read()));
                        submittedSources.add(source);
                    }
                    case MDNS -> {
                        futures.add(executor.submit(() -> mdnsProbe.probe(req.durationSeconds())));
                        submittedSources.add(source);
                    }
                    case PCAP -> {
                        futures.add(executor.submit(() -> {
                            try {
                                return pcapSniffer.sniff(req.iface(), req.durationSeconds());
                            } catch (PcapNativeException | NotOpenException e) {
                                throw new DiscoveryUnavailableException(
                                    "PCAP capture failed on interface '" + req.iface() + "': " + e.getMessage(), e);
                            }
                        }));
                        submittedSources.add(source);
                    }
                    case LLDP_UNTESTED -> {
                        if (!lldpEnabled) {
                            log.warn("LLDP source requested but disabled by feature flag; skipping");
                        } else {
                            log.warn("LLDP enabled but untested — dispatching decoder (undefined behavior)");
                            futures.add(executor.submit(() -> {
                                lldpDecoder.decode(new byte[0]); // throws UnsupportedOperationException
                                return List.<DiscoveredNeighbor>of();
                            }));
                            submittedSources.add(source);
                        }
                    }
                    case CDP_UNTESTED -> {
                        if (!cdpEnabled) {
                            log.warn("CDP source requested but disabled by feature flag; skipping");
                        } else {
                            log.warn("CDP enabled but untested — dispatching decoder (undefined behavior)");
                            futures.add(executor.submit(() -> {
                                cdpDecoder.decode(new byte[0]); // throws UnsupportedOperationException
                                return List.<DiscoveredNeighbor>of();
                            }));
                            submittedSources.add(source);
                        }
                    }
                }
            }

            // Collect results
            for (int i = 0; i < futures.size(); i++) {
                DiscoverySource source = submittedSources.get(i);
                try {
                    List<DiscoveredNeighbor> neighbors = futures.get(i).get();
                    Instant observedAt = clock.instant();
                    for (DiscoveredNeighbor n : neighbors) {
                        Discovery disc = toDiscovery(n, source, observedAt);
                        perSourceCount.merge(source, 1, Integer::sum);
                        discoveredByIp.put(disc.ipAddress(), disc); // last-write-wins for dedup
                    }
                } catch (ExecutionException ex) {
                    Throwable cause = ex.getCause();
                    if (cause instanceof DiscoveryUnavailableException due) {
                        throw due;
                    }
                    throw new DiscoveryUnavailableException(
                        "Discovery source " + source + " failed: " + cause.getMessage(), cause);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new DiscoveryUnavailableException("Sweep interrupted", e);
                }
            }
        }

        // Upsert unique discoveries — single batch round-trip via upsertAll
        List<Long> deviceIds = new ArrayList<>();
        if (!discoveredByIp.isEmpty()) {
            List<Discovery> batch = new ArrayList<>(discoveredByIp.values());
            List<Device> persisted = upsertService.upsertAll(batch);
            for (Device d : persisted) {
                deviceIds.add(d.getId());
            }
        }

        // Emit audit event
        long sweepId = clock.millis();
        auditService.recordEvent(
            "discovery",
            "PASSIVE_SWEEP",
            "discovery",
            String.valueOf(sweepId),
            Map.of(
                "iface", req.iface() == null ? "" : req.iface(),
                "durationSeconds", req.durationSeconds(),
                "sources", req.sources(),
                "perSourceCount", perSourceCount,
                "totalDiscovered", discoveredByIp.size()
            )
        );

        return new PassiveDiscoveryResponse(discoveredByIp.size(), deviceIds, perSourceCount);
    }

    private Discovery toDiscovery(DiscoveredNeighbor n, DiscoverySource source, Instant observedAt) {
        // For MDNS, the hostname comes from the neighbor; for ARP/PCAP it's null
        String hostname = (source == DiscoverySource.MDNS) ? n.iface() : null; // iface field unused for MDNS
        return new Discovery(n.ipAddress(), n.macAddress(), null, source, observedAt);
    }
}
