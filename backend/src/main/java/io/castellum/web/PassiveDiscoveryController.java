package io.castellum.web;

import io.castellum.discovery.*;
import io.castellum.web.dto.DiscoverySourceDto;
import io.castellum.web.dto.DiscoverySweepDto;
import io.castellum.web.dto.PassiveDiscoveryRequestDto;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

@RestController
@RequestMapping("/api/discovery")
public class PassiveDiscoveryController {

    private static final int DEFAULT_DURATION_SECONDS = 30;
    private static final List<DiscoverySource> DEFAULT_SOURCES =
        List.of(DiscoverySource.ARP, DiscoverySource.MDNS);

    private final PassiveDiscoveryService service;
    private final DiscoverySweepRepository sweepRepo;
    private final Clock clock;
    private final boolean pcapEnabled;
    private final boolean lldpEnabled;
    private final boolean cdpEnabled;

    public PassiveDiscoveryController(PassiveDiscoveryService service,
                                 DiscoverySweepRepository sweepRepo,
                                 Clock clock,
                                 @Value("${castellum.discovery.pcap.enabled:false}") boolean pcapEnabled,
                                 @Value("${castellum.discovery.lldp.enabled:false}") boolean lldpEnabled,
                                 @Value("${castellum.discovery.cdp.enabled:false}") boolean cdpEnabled) {
        this.service = service;
        this.sweepRepo = sweepRepo;
        this.clock = clock;
        this.pcapEnabled = pcapEnabled;
        this.lldpEnabled = lldpEnabled;
        this.cdpEnabled = cdpEnabled;
    }

    @PostMapping("/passive")
    @PreAuthorize("hasRole('ADMIN')")
    public PassiveDiscoveryResponse passive(@Valid @RequestBody PassiveDiscoveryRequestDto dto)
            throws DiscoveryUnavailableException {
        PassiveDiscoveryRequest req = normalize(dto);
        return service.sweep(req);
    }

    /**
     * Reports the configured availability of each discovery source. ARP and mDNS are
     * always reported {@code enabled=true} (Linux always has the readers wired up;
     * non-Linux hosts get the OS-specific reader from {@link ArpReaderFactory}). PCAP
     * reflects {@code castellum.discovery.pcap.enabled}; LLDP/CDP reflect their feature flags.
     *
     * <p>VIEWER role — operators inspecting which probes will fire.
     */
    @GetMapping("/sources")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public List<DiscoverySourceDto> sources() {
        return List.of(
            new DiscoverySourceDto("ARP", true, "Host ARP cache (OS-portable: Linux /proc/net/arp, macOS arp -an, Windows arp -a)"),
            new DiscoverySourceDto("MDNS", true, "Multicast DNS service browser"),
            new DiscoverySourceDto("PCAP", pcapEnabled, pcapEnabled
                ? "Packet capture (requires CAP_NET_RAW)"
                : "Disabled by castellum.discovery.pcap.enabled"),
            new DiscoverySourceDto("LLDP", lldpEnabled, lldpEnabled
                ? "Link Layer Discovery Protocol (managed-switch profile)"
                : "Disabled by castellum.discovery.lldp.enabled"),
            new DiscoverySourceDto("CDP", cdpEnabled, cdpEnabled
                ? "Cisco Discovery Protocol (managed-switch profile)"
                : "Disabled by castellum.discovery.cdp.enabled")
        );
    }

    /**
     * Lists discovery sweeps started after {@code since} (default = now − 24h),
     * ordered by start time descending. VIEWER role.
     */
    @GetMapping("/sweeps")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public List<DiscoverySweepDto> sweeps(
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant since) {
        Instant cutoff = since != null ? since : clock.instant().minus(Duration.ofHours(24));
        return sweepRepo.findByStartedAtAfterOrderByStartedAtDesc(cutoff)
            .stream().map(this::toDto).toList();
    }

    private DiscoverySweepDto toDto(DiscoverySweep s) {
        return new DiscoverySweepDto(
            s.getId(), s.getStartedAt(), s.getFinishedAt(),
            s.getSource(), s.getIface(),
            s.getNeighborCount(), s.getDeviceCount(),
            s.getTriggeredBy(), s.getAuditLogId(), s.getStatus());
    }

    private PassiveDiscoveryRequest normalize(PassiveDiscoveryRequestDto dto) {
        int duration = (dto.durationSeconds() <= 0) ? DEFAULT_DURATION_SECONDS : dto.durationSeconds();
        List<DiscoverySource> sources = (dto.sources() == null || dto.sources().isEmpty())
            ? DEFAULT_SOURCES : dto.sources();
        return new PassiveDiscoveryRequest(dto.iface(), duration, sources);
    }
}
