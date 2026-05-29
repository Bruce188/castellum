package io.castellum.web;

import io.castellum.audit.AuditService;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import io.castellum.scan.CidrValidator;
import io.castellum.scan.ScanExecutionService;
import io.castellum.scan.ScanReportService;
import io.castellum.scan.ScanSizeGuard;
import io.castellum.scan.ScanSubmissionRateLimiter;
import io.castellum.web.dto.ScanDetailDto;
import io.castellum.web.dto.ScanReportDto;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.RejectedExecutionException;

@RestController
public class ScanController {

    private static final Logger log = LoggerFactory.getLogger(ScanController.class);

    private final ScanRepository scanRepository;
    private final AuditService auditService;
    private final ScanExecutionService scanExecutionService;
    private final ScanSubmissionRateLimiter scanRateLimiter;
    private final DeviceRepository deviceRepository;
    private final ScanReportService scanReportService;

    public ScanController(ScanRepository scanRepository,
                          AuditService auditService,
                          ScanExecutionService scanExecutionService,
                          ScanSubmissionRateLimiter scanRateLimiter,
                          DeviceRepository deviceRepository,
                          ScanReportService scanReportService) {
        this.scanRepository = scanRepository;
        this.auditService = auditService;
        this.scanExecutionService = scanExecutionService;
        this.scanRateLimiter = scanRateLimiter;
        this.deviceRepository = deviceRepository;
        this.scanReportService = scanReportService;
    }

    @PostMapping("/api/scan")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> submit(@Valid @RequestBody ScanRequest request,
                                    Authentication auth) {
        // 1. Structural CIDR validity (IllegalArgumentException → 400 via GlobalExceptionHandler).
        CidrValidator.requireValid(request.cidr());

        // 2. Scope guard — reject /16, /20, etc. (ScanScopeTooLargeException → 400).
        ScanSizeGuard.requireBoundedScope(request.cidr());

        // 3. Per-actor rate-limit (20 / hour). On block: 429 + Retry-After.
        String actor = auth == null || auth.getName() == null ? "system" : auth.getName();
        if (!scanRateLimiter.tryAcquire(actor)) {
            long retryAfter = scanRateLimiter.retryAfterSeconds(actor);
            auditService.recordEvent(actor, "SCAN_RATE_LIMIT", "scan", "-",
                Map.of("retryAfter", retryAfter));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", String.valueOf(retryAfter))
                .build();
        }
        scanRateLimiter.recordSubmission(actor);

        Scan scan = new Scan();
        scan.setCidr(request.cidr());
        scan.setScanType(request.type().name());
        scan.setStatus(ScanStatus.PENDING);
        scan.setRequestedAt(Instant.now());

        Scan saved = scanRepository.save(scan);
        auditService.recordEvent(actor, "SCAN_SUBMIT", "scan", String.valueOf(saved.getId()), saved);

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
    public ScanDetailDto getById(@PathVariable Long id) {
        Scan scan = scanRepository.findById(id)
            .orElseThrow(NoSuchElementException::new);
        // AC1: precise attribution via lastSeenByScanId — heuristic findIdsByFirstSeenBetween removed
        List<Long> ids = deviceRepository.findIdsByLastSeenByScanId(id);
        return new ScanDetailDto(
            scan.getId(), scan.getCidr(), scan.getScanType(), scan.getStatus(),
            scan.getRequestedAt(), scan.getCompletedAt(),
            scan.getFailureReason(), scan.getRetryCount(),
            ids);
    }

    @GetMapping("/api/scans/{id}/report")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public ScanReportDto report(@PathVariable Long id) {
        // Stub — delegates to ScanReportService which returns null until implemented
        return scanReportService.buildReport(id);
    }

    @GetMapping("/api/scans")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public Page<Scan> list(@PageableDefault(size = 100) Pageable pageable) {
        return scanRepository.findAll(pageable);
    }
}
