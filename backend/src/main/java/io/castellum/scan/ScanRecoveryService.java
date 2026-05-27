package io.castellum.scan;

import io.castellum.audit.AuditService;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.RejectedExecutionException;

/**
 * Boot-time recovery for scans orphaned by a previous JVM restart.
 *
 * <p>On {@link ApplicationReadyEvent}, scans that were left in {@code PENDING} or in a
 * stale {@code RUNNING} state (their {@code requestedAt} predates this process) are
 * reclaimed via a guarded compare-and-set and re-dispatched through
 * {@link ScanExecutionService#executeAsync(Long)}. A single {@code SCAN_RECOVERY} audit
 * event records how many scans were requeued.
 *
 * <p>Idempotency is guaranteed at two layers:
 * <ol>
 *   <li>This hook fires once at boot — {@code COMPLETE} scans are never in the recovery
 *       set so a second restart cannot re-execute a completed scan.</li>
 *   <li>Each row is claimed via {@link ScanRepository#claimForRecovery(Long, ScanStatus)};
 *       if a concurrent actor has already changed the status, the CAS returns 0 and
 *       {@code executeAsync} is not called for that row.</li>
 * </ol>
 */
@Component
public class ScanRecoveryService {

    private static final Logger log = LoggerFactory.getLogger(ScanRecoveryService.class);

    private final ScanRepository scanRepository;
    private final ScanExecutionService scanExecutionService;
    private final AuditService auditService;
    private final Clock clock;
    private final Instant processStart;

    public ScanRecoveryService(ScanRepository scanRepository,
                               @Lazy ScanExecutionService scanExecutionService,
                               AuditService auditService,
                               Clock clock) {
        this.scanRepository = scanRepository;
        this.scanExecutionService = scanExecutionService;
        this.auditService = auditService;
        this.clock = clock;
        this.processStart = clock.instant(); // captured ONCE at construction, before ApplicationReadyEvent
    }

    /**
     * Called by Spring on {@link ApplicationReadyEvent}. Finds all recoverable scans,
     * claims each via CAS, dispatches execution for successfully claimed rows, and
     * emits a single {@code SCAN_RECOVERY} audit record.
     */
    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void recoverInterruptedScans() {
        List<Scan> candidates = scanRepository.findRecoverable(processStart);

        int pendingCount = 0;
        int staleCount = 0;
        int requeued = 0;

        for (Scan scan : candidates) {
            ScanStatus observed = scan.getStatus();

            if (observed == ScanStatus.PENDING) {
                pendingCount++;
            } else if (observed == ScanStatus.RUNNING) {
                staleCount++;
            }

            int claimed = scanRepository.claimForRecovery(scan.getId(), observed);
            if (claimed == 1) {
                try {
                    scanExecutionService.executeAsync(scan.getId());
                } catch (RejectedExecutionException e) {
                    log.warn("scan {} recovery dispatch rejected by executor — row stays PENDING",
                        scan.getId());
                }
                requeued++;
            } else {
                log.debug("scan {} skipped recovery — status changed by concurrent actor", scan.getId());
            }
        }

        auditService.recordEvent("system", "SCAN_RECOVERY", "scan", "-",
            Map.of("requeued", requeued,
                   "pending", pendingCount,
                   "staleRunning", staleCount,
                   "processStart", processStart.toString()));

        log.info("Scan recovery complete: {} candidates ({} pending, {} stale-running), {} requeued",
            candidates.size(), pendingCount, staleCount, requeued);
    }
}
