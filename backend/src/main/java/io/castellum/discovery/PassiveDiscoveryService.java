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

    private final ArpReaderFactory arpFactory;
    private final MdnsProbe mdnsProbe;
    private final PcapSniffer pcapSniffer;
    private final LldpDecoder lldpDecoder;
    private final LldpCapture lldpCapture;
    private final CdpDecoder cdpDecoder;
    private final ConnTableReader connTableReader;
    private final GatewayProbe gatewayProbe;
    private final DeviceUpsertService upsertService;
    private final AuditService auditService;
    private final DiscoverySweepRecorder recorder;
    private final boolean lldpEnabled;
    private final boolean cdpEnabled;
    private final boolean pcapEnabled;
    private final boolean connTableEnabled;
    private final Clock clock;

    public PassiveDiscoveryService(
            ArpReaderFactory arpFactory,
            MdnsProbe mdnsProbe,
            PcapSniffer pcapSniffer,
            LldpDecoder lldpDecoder,
            LldpCapture lldpCapture,
            CdpDecoder cdpDecoder,
            ConnTableReader connTableReader,
            GatewayProbe gatewayProbe,
            DeviceUpsertService upsertService,
            AuditService auditService,
            DiscoverySweepRecorder recorder,
            @Value("${castellum.discovery.lldp.enabled:false}") boolean lldpEnabled,
            @Value("${castellum.discovery.cdp.enabled:false}") boolean cdpEnabled,
            @Value("${castellum.discovery.pcap.enabled:false}") boolean pcapEnabled,
            @Value("${castellum.discovery.conn-table.enabled:true}") boolean connTableEnabled,
            Clock clock) {
        this.arpFactory = arpFactory;
        this.mdnsProbe = mdnsProbe;
        this.pcapSniffer = pcapSniffer;
        this.lldpDecoder = lldpDecoder;
        this.lldpCapture = lldpCapture;
        this.cdpDecoder = cdpDecoder;
        this.connTableReader = connTableReader;
        this.gatewayProbe = gatewayProbe;
        this.upsertService = upsertService;
        this.auditService = auditService;
        this.recorder = recorder;
        this.lldpEnabled = lldpEnabled;
        this.cdpEnabled = cdpEnabled;
        this.pcapEnabled = pcapEnabled;
        this.connTableEnabled = connTableEnabled;
        this.clock = clock;
    }

    /**
     * Runs a bounded passive sweep and returns a summary of what was discovered.
     *
     * @throws DiscoveryUnavailableException if a required capability (CAP_NET_RAW, libpcap) is absent
     */
    public PassiveDiscoveryResponse sweep(PassiveDiscoveryRequest req) throws DiscoveryUnavailableException {
        return internalSweep(req, "MANUAL");
    }

    /**
     * Scheduler-path entry point. Constructs a default ARP + CONN_TABLE + GATEWAY request
     * (the local-read sources that need no interface or duration) and threads
     * {@code triggered_by=SCHEDULER} into the sweep audit row. Never returns null.
     */
    public PassiveDiscoveryResponse scheduledSweep() throws DiscoveryUnavailableException {
        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(null, 30,
            List.of(DiscoverySource.ARP, DiscoverySource.CONN_TABLE, DiscoverySource.GATEWAY));
        return internalSweep(req, "SCHEDULER");
    }

    private PassiveDiscoveryResponse internalSweep(PassiveDiscoveryRequest req, String triggeredBy)
            throws DiscoveryUnavailableException {
        // Validate PCAP-specific precondition before opening a sweep row — invalid input
        // produces an HTTP 400 / DiscoveryUnavailable, not a row in discovery_sweep.
        // When pcap is disabled by flag the source is soft-skipped inside runSweep so we don't
        // need iface here.
        if (pcapEnabled
                && req.sources().contains(DiscoverySource.PCAP)
                && (req.iface() == null || req.iface().isBlank())) {
            throw new DiscoveryUnavailableException("PCAP source requires interface name");
        }
        // Same intake validation for LLDP — a live capture cannot open a null/blank interface.
        // When LLDP is disabled by flag the source is soft-skipped inside runSweep.
        if (lldpEnabled
                && req.sources().contains(DiscoverySource.LLDP)
                && (req.iface() == null || req.iface().isBlank())) {
            throw new DiscoveryUnavailableException("LLDP source requires interface name");
        }

        String joinedSources = req.sources().stream()
            .map(Enum::name).reduce((a, b) -> a + "," + b).orElse("");
        Long sweepId = recorder.start(joinedSources, req.iface(), triggeredBy);

        try {
            return runSweep(req, sweepId);
        } catch (DiscoveryUnavailableException due) {
            recorder.finish(sweepId, "UNAVAILABLE", 0, 0, null, req.iface());
            throw due;
        } catch (RuntimeException e) {
            log.error("Passive sweep {} failed", sweepId, e);
            recorder.finish(sweepId, "FAILED", 0, 0, null, req.iface());
            throw e;
        }
    }

    private PassiveDiscoveryResponse runSweep(PassiveDiscoveryRequest req, Long sweepId)
            throws DiscoveryUnavailableException {
        Map<DiscoverySource, Integer> perSourceCount = new EnumMap<>(DiscoverySource.class);
        for (DiscoverySource src : req.sources()) {
            perSourceCount.put(src, 0);
        }

        // MAC-primary dedupe: rows with a MAC collapse on the MAC key (handles IP-renumber events
        // and multi-source observations of the same NIC). Rows without a MAC fall back to IP key.
        Map<String, Discovery> withMac = new LinkedHashMap<>();
        Map<String, Discovery> withoutMac = new LinkedHashMap<>();
        List<Future<List<DiscoveredNeighbor>>> futures = new ArrayList<>();
        List<DiscoverySource> submittedSources = new ArrayList<>();

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (DiscoverySource source : req.sources()) {
                switch (source) {
                    case ARP -> {
                        futures.add(executor.submit(() -> arpFactory.select().read()));
                        submittedSources.add(source);
                    }
                    case MDNS -> {
                        futures.add(executor.submit(() -> mdnsProbe.probe(req.durationSeconds())));
                        submittedSources.add(source);
                    }
                    case PCAP -> {
                        if (!pcapEnabled) {
                            log.info("PCAP source requested but disabled by flag; skipping");
                            break;
                        }
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
                    case LLDP -> {
                        if (!lldpEnabled) {
                            log.info("LLDP source requested but disabled by feature flag; skipping");
                            break;
                        }
                        futures.add(executor.submit(() -> {
                            try {
                                return lldpCapture.capture(req.iface(), req.durationSeconds());
                            } catch (PcapNativeException | NotOpenException e) {
                                throw new DiscoveryUnavailableException(
                                    "LLDP capture failed on interface '" + req.iface() + "': " + e.getMessage(), e);
                            }
                        }));
                        submittedSources.add(source);
                    }
                    case CDP -> {
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
                    case CONN_TABLE -> {
                        if (!connTableEnabled) {
                            log.info("CONN_TABLE source requested but disabled by flag; skipping");
                            break;
                        }
                        futures.add(executor.submit(() -> connTableReader.read()));
                        submittedSources.add(source);
                    }
                    case GATEWAY -> {
                        futures.add(executor.submit(() -> gatewayProbe.probe()));
                        submittedSources.add(source);
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
                        boolean ipBlank = n.ipAddress() == null || n.ipAddress().isBlank();
                        boolean macBlank = n.macAddress() == null || n.macAddress().isBlank();
                        // Hostname-only entries (no IP, no MAC) cannot key the device upsert —
                        // skip but still count toward perSourceCount so operators see them in audit.
                        if (ipBlank && macBlank) {
                            perSourceCount.merge(source, 1, Integer::sum);
                            log.debug("Skipping unkeyable neighbor (no IP, no MAC): hostname={}", n.hostname());
                            continue;
                        }
                        // MAC-only neighbor (LLDP/CDP infrastructure without a management address):
                        // keep it, keyed by the deterministic synthetic placeholder IP. It carries
                        // a MAC, so it lands in the withMac map below.
                        String ip = ipBlank ? PlaceholderIp.forMac(n.macAddress()) : n.ipAddress();
                        Discovery disc = toDiscovery(n, source, observedAt, ip);
                        perSourceCount.merge(source, 1, Integer::sum);
                        if (disc.macAddress() != null && !disc.macAddress().isBlank()) {
                            // IP-quality-aware merge on MAC: a placeholder-IP observation must
                            // never displace a real-IP observation for the same MAC (and a real
                            // IP replaces a placeholder), with hostname/iface backfilled
                            // fill-when-null from the losing row. Same-quality collisions keep
                            // plain last-write-wins.
                            withMac.merge(disc.macAddress(), disc, PassiveDiscoveryService::mergeOnMac);
                        } else {
                            withoutMac.put(disc.ipAddress(), disc); // fallback IP key
                        }
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

        reconcileMacPrimacy(withMac, withoutMac);

        // Upsert unique discoveries — single batch round-trip via upsertAll
        List<Long> deviceIds = new ArrayList<>();
        List<Discovery> batch = new ArrayList<>(withMac.size() + withoutMac.size());
        batch.addAll(withMac.values());
        batch.addAll(withoutMac.values());
        // Count from the reconciled batch — summing the two map sizes would double-count
        // an IP observed by both a MAC-bearing and a null-MAC source.
        int totalDeduped = batch.size();
        if (totalDeduped > 0) {
            List<Device> persisted = upsertService.upsertAll(batch);
            for (Device d : persisted) {
                deviceIds.add(d.getId());
            }
        }

        // Derive observed iface from the deduped batch: first non-blank iface among collected
        // neighbors (option a — records the interface the sweep actually observed on, truthful
        // for both manual and scheduled paths; null when no neighbors carried an iface).
        String observedIface = batch.stream()
            .map(Discovery::iface)
            .filter(s -> s != null && !s.isBlank())
            .findFirst().orElse(null);

        // Emit audit event — sweepId now references the discovery_sweep row created at start.
        io.castellum.audit.AuditLog auditLog = auditService.recordEvent(
            "discovery",
            "PASSIVE_SWEEP",
            "discovery",
            String.valueOf(sweepId),
            Map.of(
                "iface", req.iface() == null ? "" : req.iface(),
                "durationSeconds", req.durationSeconds(),
                "sources", req.sources(),
                "perSourceCount", perSourceCount,
                "totalDiscovered", totalDeduped
            )
        );
        Long auditLogId = auditLog == null ? null : auditLog.getId();
        recorder.finish(sweepId, "OK", totalDeduped, deviceIds.size(), auditLogId, observedIface);

        return new PassiveDiscoveryResponse(totalDeduped, deviceIds, perSourceCount, sweepId);
    }

    /**
     * Drops every IP-keyed (null-MAC) entry whose IP already appears among the MAC-keyed
     * entries — the MAC-bearing observation supersedes, carrying strictly more information.
     * Without this, the gateway (virtually always present in the ARP cache) would enter the
     * upsert batch twice — ARP row with MAC plus GATEWAY/CONN_TABLE row without — and on a
     * first sweep both rows would INSERT and violate the {@code device_ip_origin_unique}
     * constraint. Hostname/iface from a dropped row backfill the surviving entry when it
     * lacks them (fill-when-null, mirroring upsert semantics), so e.g. an mDNS hostname is
     * not lost to a bare ARP row for the same IP.
     */
    private void reconcileMacPrimacy(Map<String, Discovery> withMac, Map<String, Discovery> withoutMac) {
        if (withMac.isEmpty() || withoutMac.isEmpty()) {
            return;
        }
        Map<String, String> macKeyByIp = new HashMap<>();
        for (Map.Entry<String, Discovery> e : withMac.entrySet()) {
            macKeyByIp.put(e.getValue().ipAddress(), e.getKey());
        }
        Iterator<Discovery> ipKeyed = withoutMac.values().iterator();
        while (ipKeyed.hasNext()) {
            Discovery dropped = ipKeyed.next();
            String macKey = macKeyByIp.get(dropped.ipAddress());
            if (macKey == null) {
                continue;
            }
            Discovery kept = withMac.get(macKey);
            String hostname = kept.hostname() != null ? kept.hostname() : dropped.hostname();
            String iface = kept.iface() != null ? kept.iface() : dropped.iface();
            if (!Objects.equals(hostname, kept.hostname()) || !Objects.equals(iface, kept.iface())) {
                withMac.put(macKey, new Discovery(kept.ipAddress(), kept.macAddress(), hostname,
                    kept.source(), kept.observedAt(), iface, kept.publishesHostPort()));
            }
            ipKeyed.remove();
        }
    }

    /**
     * Resolves a same-sweep collision between two MAC-keyed discoveries. When exactly one
     * side carries a synthetic placeholder IP ({@link PlaceholderIp}), the real-IP side wins
     * regardless of arrival order — an LLDP MAC-only row must never overwrite an ARP row that
     * knows the device's actual address. Hostname and iface backfill fill-when-null from the
     * losing row (mirroring {@link #reconcileMacPrimacy}), so e.g. an LLDP sysname survives
     * onto the ARP entry. When both sides are placeholder or both are real, the incoming row
     * wins (last-write-wins, unchanged behavior).
     */
    private static Discovery mergeOnMac(Discovery existing, Discovery incoming) {
        boolean existingPlaceholder = PlaceholderIp.isPlaceholder(existing.ipAddress());
        boolean incomingPlaceholder = PlaceholderIp.isPlaceholder(incoming.ipAddress());
        if (existingPlaceholder == incomingPlaceholder) {
            return incoming; // same IP quality — last-write-wins on MAC
        }
        Discovery winner = existingPlaceholder ? incoming : existing;
        Discovery loser = existingPlaceholder ? existing : incoming;
        String hostname = winner.hostname() != null ? winner.hostname() : loser.hostname();
        String iface = winner.iface() != null ? winner.iface() : loser.iface();
        if (Objects.equals(hostname, winner.hostname()) && Objects.equals(iface, winner.iface())) {
            return winner;
        }
        return new Discovery(winner.ipAddress(), winner.macAddress(), hostname,
            winner.source(), winner.observedAt(), iface, winner.publishesHostPort());
    }

    private Discovery toDiscovery(DiscoveredNeighbor n, DiscoverySource source, Instant observedAt, String ipAddress) {
        return new Discovery(ipAddress, n.macAddress(), n.hostname(), source, observedAt, n.iface(), false);
    }
}
