package io.castellum.web;

import io.castellum.discovery.*;
import io.castellum.web.dto.ActiveCidrDto;
import io.castellum.web.dto.DiscoverySourceDto;
import io.castellum.web.dto.DiscoverySweepDto;
import io.castellum.web.dto.InterfaceInfoDto;
import io.castellum.web.dto.PassiveDiscoveryRequestDto;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.net.Inet4Address;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
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
    private final ActiveNetworkDetector activeNetworkDetector;
    private final DockerDiscoveryService dockerDiscoveryService;

    public PassiveDiscoveryController(PassiveDiscoveryService service,
                                 DiscoverySweepRepository sweepRepo,
                                 Clock clock,
                                 @Value("${castellum.discovery.pcap.enabled:false}") boolean pcapEnabled,
                                 @Value("${castellum.discovery.lldp.enabled:false}") boolean lldpEnabled,
                                 @Value("${castellum.discovery.cdp.enabled:false}") boolean cdpEnabled,
                                 ActiveNetworkDetector activeNetworkDetector,
                                 DockerDiscoveryService dockerDiscoveryService) {
        this.service = service;
        this.sweepRepo = sweepRepo;
        this.clock = clock;
        this.pcapEnabled = pcapEnabled;
        this.lldpEnabled = lldpEnabled;
        this.cdpEnabled = cdpEnabled;
        this.activeNetworkDetector = activeNetworkDetector;
        this.dockerDiscoveryService = dockerDiscoveryService;
    }

    @PostMapping("/passive")
    @PreAuthorize("hasRole('ADMIN')")
    public PassiveDiscoveryResponse passive(@Valid @RequestBody PassiveDiscoveryRequestDto dto)
            throws DiscoveryUnavailableException {
        PassiveDiscoveryRequest req = normalize(dto);
        return service.sweep(req);
    }

    /**
     * Discovers running Docker containers via the local {@code docker} CLI and upserts each as
     * a {@link io.castellum.domain.Device} so the topology renders the containers (one star per
     * docker network, host-bridged only when a container publishes a port). Idempotent —
     * re-running updates devices in place.
     *
     * <p>ADMIN-only, mirroring {@code POST /api/discovery/passive}. Returns the
     * discovered/updated count. A {@link DiscoveryUnavailableException} (docker absent /
     * daemon unreachable) maps to its configured HTTP status via {@link GlobalExceptionHandler}.
     */
    @PostMapping("/docker")
    @PreAuthorize("hasRole('ADMIN')")
    public DockerDiscoveryResponse docker() throws DiscoveryUnavailableException {
        return dockerDiscoveryService.discover();
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
     * Lists the host's up, non-loopback network interfaces — the menu of choices
     * for the {@code iface} field on {@code POST /api/discovery/passive}.
     *
     * <p>ADMIN-only: surface-area for write operations. Returns an empty list
     * (never null) if {@link NetworkInterface#getNetworkInterfaces()} throws or
     * yields no qualifying interfaces.
     */
    @GetMapping("/interfaces")
    @PreAuthorize("hasRole('ADMIN')")
    public List<InterfaceInfoDto> interfaces() {
        List<InterfaceInfoDto> out = new ArrayList<>();
        try {
            var nics = NetworkInterface.getNetworkInterfaces();
            if (nics == null) return out;
            for (NetworkInterface nic : Collections.list(nics)) {
                try {
                    if (!nic.isUp() || nic.isLoopback()) continue;
                    String ipAddress = null;
                    int prefix = 0;
                    for (InterfaceAddress ia : nic.getInterfaceAddresses()) {
                        if (ia.getAddress() instanceof Inet4Address) {
                            ipAddress = ia.getAddress().getHostAddress();
                            prefix = ia.getNetworkPrefixLength();
                            break;
                        }
                    }
                    out.add(new InterfaceInfoDto(nic.getName(), nic.getDisplayName(), nic.getMTU(),
                        ipAddress, prefix));
                } catch (SocketException ignored) {
                    // Skip this interface — it disappeared between enumeration and inspection.
                }
            }
        } catch (SocketException ignored) {
            // Best-effort enumeration; return what we have so far.
        }
        return out;
    }

    /**
     * Returns the host's primary-interface CIDR derived from {@code /proc/net/route}.
     *
     * <p>VIEWER and ADMIN — read-only introspection; needed to pre-fill the scan form
     * for any authenticated user. The scan POST is separately RBAC-guarded.
     *
     * <p>Returns the documented empty shape ({@code prefix=0}, all strings null) when
     * the host is non-Linux or has no default route. Never returns 204.
     */
    @GetMapping("/active-cidr")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public ActiveCidrDto activeCidr() {
        return activeNetworkDetector.detect()
            .map(n -> new ActiveCidrDto(n.iface(), n.cidr(), n.ipAddress(), n.prefix(), n.note()))
            .orElse(new ActiveCidrDto(null, null, null, 0, null));
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
