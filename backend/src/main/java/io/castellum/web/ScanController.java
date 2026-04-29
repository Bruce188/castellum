package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import io.castellum.scan.CidrValidator;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;

import java.time.Instant;
import java.util.Map;
import java.util.NoSuchElementException;

@RestController
public class ScanController {

    private final ScanRepository scanRepository;
    private final AuditService auditService;

    public ScanController(ScanRepository scanRepository, AuditService auditService) {
        this.scanRepository = scanRepository;
        this.auditService = auditService;
    }

    @PostMapping("/api/scan")
    public ResponseEntity<Map<String, Long>> submit(@Valid @RequestBody ScanRequest request) {
        CidrValidator.requireValid(request.cidr());

        Scan scan = new Scan();
        scan.setCidr(request.cidr());
        scan.setScanType(request.type().name());
        scan.setStatus(ScanStatus.PENDING);
        scan.setRequestedAt(Instant.now());

        Scan saved = scanRepository.save(scan);
        auditService.recordEvent("system", "SCAN_SUBMIT", "scan", String.valueOf(saved.getId()), saved);
        // TODO(feature-2): wire @Async scan execution; current behavior persists PENDING only.
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of("id", saved.getId()));
    }

    @GetMapping("/api/scans/{id}")
    public Scan getById(@PathVariable Long id) {
        return scanRepository.findById(id)
            .orElseThrow(NoSuchElementException::new);
    }

    @GetMapping("/api/scans")
    public Page<Scan> list(@PageableDefault(size = 100) Pageable pageable) {
        return scanRepository.findAll(pageable);
    }
}
