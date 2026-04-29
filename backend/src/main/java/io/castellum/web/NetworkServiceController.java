package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.NoSuchElementException;

@RestController
@RequestMapping("/api/services")
@Validated
public class NetworkServiceController {

    private final NetworkServiceRepository serviceRepository;
    private final AuditService auditService;

    public NetworkServiceController(NetworkServiceRepository serviceRepository, AuditService auditService) {
        this.serviceRepository = serviceRepository;
        this.auditService = auditService;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public Object list(@RequestParam(required = false) Long deviceId,
                       @PageableDefault(size = 100) Pageable pageable) {
        if (deviceId != null) {
            return serviceRepository.findByDeviceId(deviceId);
        }
        return serviceRepository.findAll(pageable);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public NetworkService getById(@PathVariable Long id) {
        return serviceRepository.findById(id)
            .orElseThrow(NoSuchElementException::new);
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<NetworkService> create(@Valid @RequestBody NetworkService service) {
        NetworkService saved = serviceRepository.save(service);
        auditService.recordEvent("system", "SERVICE_CREATE", "service", String.valueOf(saved.getId()), saved);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest()
            .path("/{id}")
            .buildAndExpand(saved.getId())
            .toUri();
        return ResponseEntity.created(location).body(saved);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public NetworkService update(@PathVariable Long id, @Valid @RequestBody NetworkService service) {
        serviceRepository.findById(id).orElseThrow(NoSuchElementException::new);
        service.setId(id);
        NetworkService saved = serviceRepository.save(service);
        auditService.recordEvent("system", "SERVICE_UPDATE", "service", String.valueOf(saved.getId()), saved);
        return saved;
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        NetworkService existing = serviceRepository.findById(id).orElseThrow(NoSuchElementException::new);
        serviceRepository.deleteById(id);
        auditService.recordEvent("system", "SERVICE_DELETE", "service", String.valueOf(id), existing);
        return ResponseEntity.noContent().build();
    }
}
