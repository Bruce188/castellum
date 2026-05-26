package io.castellum.scan;

import io.castellum.audit.AuditService;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.RejectedExecutionException;

/**
 * Auto-retry for nmap-timeout failures.
 *
 * <p>{@link ScanExecutionService} calls {@link #scheduleRetryIfApplicable(Scan)}
 * inside its failure-handling branch. We use a backoff schedule of
 * <code>60s × 3<sup>attempt</sup></code> (so attempt 1 fires at 60s, attempt 2
 * at 180s) and cap at {@link #MAX_RETRIES} total retries.
 *
 * <p>Retries are scheduled "virtually" via a flip of {@code Scan.status} to
 * {@link ScanStatus#PENDING} with the {@code completedAt} cleared and
 * {@code retryCount} incremented. The {@link #pollDueRetries()} bean ticks
 * every 30s, finds scans whose {@code retry_next_at} has elapsed
 * (we encode it implicitly via {@code completedAt + backoff(retry_count)}),
 * and re-dispatches them through {@link ScanExecutionService}.
 *
 * <p>We piggy-back on the existing {@code completedAt} column rather than
 * adding a new column to keep the V14 migration tidy: a FAILED row that
 * still has the {@code "nmap timed out"} reason and retry_count below the
 * cap is treated as retry-eligible until {@code completedAt + backoff} elapses.
 */
@Component
public class ScanRetryService {

    private static final Logger log = LoggerFactory.getLogger(ScanRetryService.class);

    /** Substring that flags a failure as nmap-timeout (case-insensitive). */
    static final String NMAP_TIMEOUT_MARKER = "nmap timed out";

    /** Maximum retry attempts. */
    public static final int MAX_RETRIES = 2;

    private final ScanRepository scanRepository;
    private final ScanExecutionService scanExecutionService;
    private final AuditService auditService;
    private final Clock clock;

    public ScanRetryService(ScanRepository scanRepository,
                            @Lazy ScanExecutionService scanExecutionService,
                            AuditService auditService,
                            Clock clock) {
        this.scanRepository = scanRepository;
        this.scanExecutionService = scanExecutionService;
        this.auditService = auditService;
        this.clock = clock;
    }

    /**
     * Called from {@link ScanExecutionService}'s catch-branch. If the failure
     * looks like an nmap timeout and {@code retryCount < MAX_RETRIES}, mark the
     * scan as retry-pending (status stays FAILED until the poll-tick promotes
     * it back to PENDING). Audit each scheduling event.
     */
    public void scheduleRetryIfApplicable(Scan scan) {
        String reason = scan.getFailureReason() == null ? "" : scan.getFailureReason().toLowerCase();
        if (!reason.contains(NMAP_TIMEOUT_MARKER.toLowerCase())) return;
        if (scan.getRetryCount() >= MAX_RETRIES) {
            log.info("scan {} retry cap reached ({} retries) — staying FAILED",
                scan.getId(), MAX_RETRIES);
            return;
        }
        // We don't mutate the scan here — the poll-tick decides when to flip
        // it back to PENDING. Just emit the audit row so operators see the
        // scheduling decision in the timeline.
        long backoffSeconds = backoffSecondsForAttempt(scan.getRetryCount() + 1);
        auditService.recordEvent(ScanPolicyScheduler.SCHEDULER_ACTOR, "SCAN_RETRY_SCHEDULED", "scan",
            String.valueOf(scan.getId()),
            Map.of("nextAttempt", scan.getRetryCount() + 1,
                "backoffSeconds", backoffSeconds));
    }

    /** Backoff: 60s for attempt 1, 180s for attempt 2 (60 × 3^(n-1)). */
    static long backoffSecondsForAttempt(int attempt) {
        long seconds = 60L;
        for (int i = 1; i < attempt; i++) {
            seconds *= 3L;
        }
        return seconds;
    }

    /**
     * Poller — every 30s, scans FAILED rows whose retry budget remains and
     * whose backoff has elapsed; flips them to PENDING + increments retry_count
     * + re-dispatches via {@link ScanExecutionService}. Audits {@code SCAN_RETRY}.
     */
    @Scheduled(fixedDelayString = "${castellum.scan-retry.poll-interval-millis:30000}")
    public void pollDueRetries() {
        try {
            promoteDueRetries();
        } catch (RuntimeException e) {
            log.error("scan-retry tick failed: {}", e.getMessage(), e);
        }
    }

    /** Visible for tests — drives off the injected Clock. */
    public void promoteDueRetries() {
        Instant now = clock.instant();
        for (Scan scan : scanRepository.findByStatus(ScanStatus.FAILED)) {
            if (!isRetryEligible(scan, now)) continue;
            int nextAttempt = scan.getRetryCount() + 1;
            scan.setRetryCount(nextAttempt);
            scan.setStatus(ScanStatus.PENDING);
            scan.setCompletedAt(null);
            scan.setFailureReason(null);
            scanRepository.save(scan);

            auditService.recordEvent(ScanPolicyScheduler.SCHEDULER_ACTOR, "SCAN_RETRY", "scan",
                String.valueOf(scan.getId()),
                Map.of("attempt", nextAttempt, "reason", "nmap timed out"));

            try {
                scanExecutionService.executeAsync(scan.getId());
            } catch (RejectedExecutionException e) {
                log.warn("scan {} retry dispatch rejected — row stays PENDING", scan.getId());
            }
        }
    }

    private boolean isRetryEligible(Scan scan, Instant now) {
        if (scan.getStatus() != ScanStatus.FAILED) return false;
        if (scan.getRetryCount() >= MAX_RETRIES) return false;
        String reason = scan.getFailureReason() == null ? "" : scan.getFailureReason().toLowerCase();
        if (!reason.contains(NMAP_TIMEOUT_MARKER.toLowerCase())) return false;
        if (scan.getCompletedAt() == null) return false;
        long elapsed = now.getEpochSecond() - scan.getCompletedAt().getEpochSecond();
        long backoff = backoffSecondsForAttempt(scan.getRetryCount() + 1);
        return elapsed >= backoff;
    }
}
