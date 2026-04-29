package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.risk.Criticality;
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
import java.util.NoSuchElementException;

@RestController
@RequestMapping("/api/devices")
@Validated
public class DeviceController {

    private final DeviceRepository deviceRepository;
    private final AuditService auditService;

    public DeviceController(DeviceRepository deviceRepository, AuditService auditService) {
        this.deviceRepository = deviceRepository;
        this.auditService = auditService;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public Page<Device> list(@PageableDefault(size = 100) Pageable pageable) {
        return deviceRepository.findAll(pageable);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public Device getById(@PathVariable Long id) {
        return deviceRepository.findById(id)
            .orElseThrow(NoSuchElementException::new);
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Device> create(@Valid @RequestBody Device device) {
        if (device.getCriticality() == null) device.setCriticality(Criticality.MEDIUM);
        Device saved = deviceRepository.save(device);
        auditService.recordEvent("system", "DEVICE_CREATE", "device", String.valueOf(saved.getId()), saved);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest()
            .path("/{id}")
            .buildAndExpand(saved.getId())
            .toUri();
        return ResponseEntity.created(location).body(saved);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public Device update(@PathVariable Long id, @Valid @RequestBody Device device) {
        deviceRepository.findById(id).orElseThrow(NoSuchElementException::new);
        device.setId(id);
        Device saved = deviceRepository.save(device);
        auditService.recordEvent("system", "DEVICE_UPDATE", "device", String.valueOf(saved.getId()), saved);
        return saved;
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        Device existing = deviceRepository.findById(id).orElseThrow(NoSuchElementException::new);
        deviceRepository.deleteById(id);
        auditService.recordEvent("system", "DEVICE_DELETE", "device", String.valueOf(id), existing);
        return ResponseEntity.noContent().build();
    }
}
