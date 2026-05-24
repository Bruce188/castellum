package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import io.castellum.scan.CidrValidator;
import io.castellum.scan.ScanExecutionService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;

import java.time.Instant;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.RejectedExecutionException;

@RestController
public class ScanController {

    private static final Logger log = LoggerFactory.getLogger(ScanController.class);

    private final ScanRepository scanRepository;
    private final AuditService auditService;
    private final ScanExecutionService scanExecutionService;

    public ScanController(ScanRepository scanRepository,
                          AuditService auditService,
                          ScanExecutionService scanExecutionService) {
        this.scanRepository = scanRepository;
        this.auditService = auditService;
        this.scanExecutionService = scanExecutionService;
    }

    @PostMapping("/api/scan")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Long>> submit(@Valid @RequestBody ScanRequest request) {
        CidrValidator.requireValid(request.cidr());

        Scan scan = new Scan();
        scan.setCidr(request.cidr());
        scan.setScanType(request.type().name());
        scan.setStatus(ScanStatus.PENDING);
        scan.setRequestedAt(Instant.now());

        Scan saved = scanRepository.save(scan);
        auditService.recordEvent("system", "SCAN_SUBMIT", "scan", String.valueOf(saved.getId()), saved);

        // Dispatch async execution AFTER the PENDING row is committed and audited.
        // Wrap in try/catch so TaskRejectedException (saturated queue) never surfaces to
        // the HTTP client — the PENDING row remains operator-visible for re-enqueueing.
        try {
            scanExecutionService.executeAsync(saved.getId());
        } catch (RejectedExecutionException e) {
            log.warn("Scan {} dispatch rejected (executor queue saturated) — row stays PENDING", saved.getId());
        }

        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of("id", saved.getId()));
    }

    @GetMapping("/api/scans/{id}")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public Scan getById(@PathVariable Long id) {
        return scanRepository.findById(id)
            .orElseThrow(NoSuchElementException::new);
    }

    @GetMapping("/api/scans")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public Page<Scan> list(@PageableDefault(size = 100) Pageable pageable) {
        return scanRepository.findAll(pageable);
    }
}
