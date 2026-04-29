package io.castellum.web;

import io.castellum.discovery.*;
import io.castellum.web.dto.PassiveDiscoveryRequestDto;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/discovery")
public class PassiveScanController {

    private static final int DEFAULT_DURATION_SECONDS = 30;
    private static final List<DiscoverySource> DEFAULT_SOURCES =
        List.of(DiscoverySource.ARP, DiscoverySource.MDNS);

    private final PassiveDiscoveryService service;

    public PassiveScanController(PassiveDiscoveryService service) {
        this.service = service;
    }

    @PostMapping("/passive")
    @PreAuthorize("hasRole('ADMIN')")
    public PassiveDiscoveryResponse passive(@Valid @RequestBody PassiveDiscoveryRequestDto dto) {
        PassiveDiscoveryRequest req = normalize(dto);
        return service.sweep(req);
    }

    private PassiveDiscoveryRequest normalize(PassiveDiscoveryRequestDto dto) {
        int duration = (dto.durationSeconds() <= 0) ? DEFAULT_DURATION_SECONDS : dto.durationSeconds();
        List<DiscoverySource> sources = (dto.sources() == null || dto.sources().isEmpty())
            ? DEFAULT_SOURCES : dto.sources();
        return new PassiveDiscoveryRequest(dto.iface(), duration, sources);
    }
}
