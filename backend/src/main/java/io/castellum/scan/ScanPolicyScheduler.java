package io.castellum.scan;

import io.castellum.audit.AuditService;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.RejectedExecutionException;

/**
 * Cron-driven scan-policy poller. Wakes every 60 s (configurable via
 * {@code castellum.scan-policy.poll-interval-millis}), iterates enabled
 * policies, and submits a fresh scan for any whose next-fire time has elapsed
 * since {@code lastTriggeredAt}.
 *
 * <p>Submission bypasses the per-actor rate limiter (the scheduler runs as
 * the "scheduler" system actor) but still goes through the size guard so a
 * misconfigured /16 policy fails closed at the next tick. Each successful
 * trigger emits {@code SCAN_POLICY_TRIGGER} into the audit log.
 */
@Component
public class ScanPolicyScheduler {

    private static final Logger log = LoggerFactory.getLogger(ScanPolicyScheduler.class);
    static final String SCHEDULER_ACTOR = "scheduler";

    private final ScanPolicyRepository policyRepository;
    private final ScanRepository scanRepository;
    private final ScanExecutionService scanExecutionService;
    private final AuditService auditService;
    private final Clock clock;

    public ScanPolicyScheduler(ScanPolicyRepository policyRepository,
                                ScanRepository scanRepository,
                                ScanExecutionService scanExecutionService,
                                AuditService auditService,
                                Clock clock) {
        this.policyRepository = policyRepository;
        this.scanRepository = scanRepository;
        this.scanExecutionService = scanExecutionService;
        this.auditService = auditService;
        this.clock = clock;
    }

    @Scheduled(fixedDelayString = "${castellum.scan-policy.poll-interval-millis:60000}")
    public void tick() {
        try {
            checkPolicies();
        } catch (RuntimeException e) {
            // never propagate — the @Scheduled wrapper would cancel the task on uncaught
            log.error("scan-policy tick failed: {}", e.getMessage(), e);
        }
    }

    /** Visible for tests — drives the policy-fire decision off the injected Clock. */
    public void checkPolicies() {
        Instant now = clock.instant();
        List<ScanPolicy> enabled = policyRepository.findByEnabledTrue();
        for (ScanPolicy policy : enabled) {
            try {
                if (shouldFire(policy, now)) {
                    fire(policy, now);
                }
            } catch (RuntimeException e) {
                log.warn("scan-policy {} skipped: {}", policy.getId(), e.getMessage());
            }
        }
    }

    private boolean shouldFire(ScanPolicy policy, Instant now) {
        CronExpression expr = CronExpression.parse(policy.getCronExpression());
        Instant anchor = policy.getLastTriggeredAt() != null ? policy.getLastTriggeredAt() : policy.getCreatedAt();
        if (anchor == null) anchor = now.minusSeconds(60);
        LocalDateTime next = expr.next(LocalDateTime.ofInstant(anchor, ZoneOffset.UTC));
        if (next == null) return false;
        return !LocalDateTime.ofInstant(now, ZoneOffset.UTC).isBefore(next);
    }

    private void fire(ScanPolicy policy, Instant now) {
        // Defensive: re-validate scope so a stale policy with an oversize CIDR fails closed.
        ScanSizeGuard.requireBoundedScope(policy.getCidr());

        Scan scan = new Scan();
        scan.setCidr(policy.getCidr());
        scan.setScanType(policy.getScanType());
        scan.setStatus(ScanStatus.PENDING);
        scan.setRequestedAt(now);
        Scan saved = scanRepository.save(scan);

        policy.setLastTriggeredAt(now);
        policyRepository.save(policy);

        auditService.recordEvent(SCHEDULER_ACTOR, "SCAN_POLICY_TRIGGER", "scan_policy",
            String.valueOf(policy.getId()),
            Map.of("scanId", saved.getId(), "policyName", policy.getName()));

        try {
            // requireBoundedScope above keeps policy CIDRs single-chunk today, but route
            // through the shared wide/interactive split anyway so every dispatch site
            // shares one source of truth.
            if (ScanExecutionService.isWideScan(policy.getCidr())) {
                scanExecutionService.executeWideAsync(saved.getId());
            } else {
                scanExecutionService.executeAsync(saved.getId());
            }
        } catch (RejectedExecutionException e) {
            log.warn("scan-policy {} dispatch rejected — scan {} stays PENDING",
                policy.getId(), saved.getId());
        }
    }
}
