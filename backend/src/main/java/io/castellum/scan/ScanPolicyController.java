package io.castellum.scan;

import io.castellum.audit.AuditService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.NoSuchElementException;

/**
 * ADMIN-only CRUD for cron-driven scan policies. Wired into the audit log
 * (SCAN_POLICY_CREATE / UPDATE / DELETE).
 */
@RestController
@RequestMapping("/api/scan-policy")
public class ScanPolicyController {

    private final ScanPolicyRepository repository;
    private final AuditService auditService;

    public ScanPolicyController(ScanPolicyRepository repository, AuditService auditService) {
        this.repository = repository;
        this.auditService = auditService;
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<ScanPolicyDto.Response> create(@Valid @RequestBody ScanPolicyDto.CreateRequest body,
                                                          Authentication auth) {
        // 1. Validate cron expression (Spring's CronExpression covers 6-field unix syntax).
        try {
            CronExpression.parse(body.cronExpression());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid cron expression: " + e.getMessage());
        }

        // 2. Validate CIDR structurally + scope-bound it (same gates as POST /api/scan).
        CidrValidator.requireValid(body.cidr());
        ScanSizeGuard.requireBoundedScope(body.cidr());

        // 3. Validate scanType enum membership.
        try {
            ScanType.valueOf(body.scanType());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid scanType: " + body.scanType());
        }

        if (repository.findByName(body.name()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }

        ScanPolicy policy = new ScanPolicy(
            body.name(),
            body.cronExpression(),
            body.cidr(),
            body.scanType(),
            body.enabled() == null ? Boolean.TRUE : body.enabled()
        );
        ScanPolicy saved = repository.save(policy);

        String actor = auth == null || auth.getName() == null ? "system" : auth.getName();
        auditService.recordEvent(actor, "SCAN_POLICY_CREATE", "scan_policy",
            String.valueOf(saved.getId()),
            Map.of("name", saved.getName(), "cron", saved.getCronExpression(),
                "cidr", saved.getCidr(), "scanType", saved.getScanType(),
                "enabled", saved.isEnabled()));

        return ResponseEntity.status(HttpStatus.CREATED).body(ScanPolicyDto.Response.from(saved));
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public Page<ScanPolicyDto.Response> list(@PageableDefault(size = 50) Pageable pageable) {
        return repository.findAll(pageable).map(ScanPolicyDto.Response::from);
    }

    @PutMapping("/{id}/disable")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ScanPolicyDto.Response disable(@PathVariable Long id, Authentication auth) {
        ScanPolicy policy = repository.findById(id)
            .orElseThrow(() -> new NoSuchElementException("scan_policy not found: " + id));
        policy.setEnabled(false);
        repository.save(policy);

        String actor = auth == null || auth.getName() == null ? "system" : auth.getName();
        auditService.recordEvent(actor, "SCAN_POLICY_UPDATE", "scan_policy",
            String.valueOf(id), Map.of("enabled", false));
        return ScanPolicyDto.Response.from(policy);
    }

    @PutMapping("/{id}/enable")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ScanPolicyDto.Response enable(@PathVariable Long id, Authentication auth) {
        ScanPolicy policy = repository.findById(id)
            .orElseThrow(() -> new NoSuchElementException("scan_policy not found: " + id));
        policy.setEnabled(true);
        repository.save(policy);

        String actor = auth == null || auth.getName() == null ? "system" : auth.getName();
        auditService.recordEvent(actor, "SCAN_POLICY_UPDATE", "scan_policy",
            String.valueOf(id), Map.of("enabled", true));
        return ScanPolicyDto.Response.from(policy);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<Void> delete(@PathVariable Long id, Authentication auth) {
        if (!repository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        repository.deleteById(id);

        String actor = auth == null || auth.getName() == null ? "system" : auth.getName();
        auditService.recordEvent(actor, "SCAN_POLICY_DELETE", "scan_policy",
            String.valueOf(id), Map.of());
        return ResponseEntity.noContent().build();
    }
}
