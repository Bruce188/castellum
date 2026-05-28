package io.castellum.risk;

import io.castellum.admin.InitialSyncService;
import io.castellum.cve.NvdSyncService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Component
public class RiskFeedScheduler {
    private static final Logger log = LoggerFactory.getLogger(RiskFeedScheduler.class);

    static final int MAX_RETRY_ATTEMPTS = 4;

    private final EpssIngestionService epss;
    private final KevIngestionService kev;
    private final NvdSyncService nvd;
    private final InitialSyncService initialSyncService;
    private final RiskCacheEvictor riskCacheEvictor;
    private final FeedSyncScheduleRepository repo;
    private final Clock clock;

    public RiskFeedScheduler(EpssIngestionService epss, KevIngestionService kev,
                              NvdSyncService nvd, InitialSyncService initialSyncService,
                              RiskCacheEvictor riskCacheEvictor,
                              FeedSyncScheduleRepository repo, Clock clock) {
        this.epss = epss;
        this.kev = kev;
        this.nvd = nvd;
        this.initialSyncService = initialSyncService;
        this.riskCacheEvictor = riskCacheEvictor;
        this.repo = repo;
        this.clock = clock;
    }

    /**
     * Scheduled poll tick. Wraps the entire body in try/catch(RuntimeException) so
     * no throw (malformed cron, DB I/O, backoff math) can ever cancel future firings.
     */
    @Scheduled(fixedDelayString = "${castellum.risk.poll-interval-millis:60000}")
    public void tick() {
        try {
            checkSchedule(clock.instant());
        } catch (RuntimeException e) {
            // never propagate — the @Scheduled wrapper would cancel the task on uncaught
            log.error("feed-schedule tick failed: {}", e.getMessage(), e);
        }
    }

    /** Visible for tests — drives the schedule-fire decision off an explicit Instant. */
    public void checkSchedule(Instant now) {
        FeedSyncSchedule row = repo.findById(FeedSyncSchedule.SINGLETON_ID).orElse(null);
        if (row == null) return;
        if (!row.isEnabled()) return;

        boolean fire;
        try {
            fire = shouldFire(row, now);
        } catch (RuntimeException e) {
            log.warn("feed-schedule cron unusable: {}", e.getMessage());
            return;
        }

        if (!fire) return;

        if (initialSyncService.isInFlight()) {
            log.info("scheduled feed pull skipped — manual sync in flight");
            return;
        }

        runFeedsOnce(row, now);
    }

    /** Runs the EPSS→KEV→NVD-incremental body verbatim with per-feed isolation. */
    void runFeedsOnce(FeedSyncSchedule row, Instant now) {
        boolean anyFailure = false;
        String errMsg = null;

        try {
            epss.ingest();
        } catch (Exception e) {
            log.error("EPSS ingest failed: {}", e.toString(), e);
            anyFailure = true;
            errMsg = e.getMessage();
        }

        try {
            kev.ingest();
        } catch (Exception e) {
            log.error("KEV ingest failed: {}", e.toString(), e);
            anyFailure = true;
            if (errMsg == null) errMsg = e.getMessage();
        }

        try {
            if (initialSyncService.isInFlight()) {
                log.info("Scheduled NVD incremental pull skipped — manual sync in flight");
            } else {
                nvd.incrementalPull();
            }
        } catch (Exception e) {
            log.error("NVD incremental pull failed: {}", e.toString(), e);
            anyFailure = true;
            if (errMsg == null) errMsg = e.getMessage();
        }

        // Scheduled refresh may have written new corpus rows — invalidate aggregate caches
        // (including feeds-status) so the next poll reflects the refreshed corpus.
        riskCacheEvictor.onFeedSyncComplete();

        recordOutcome(row, now, anyFailure, errMsg);
    }

    private boolean shouldFire(FeedSyncSchedule row, Instant now) {
        Instant anchor = row.getLastRunAt() != null ? row.getLastRunAt()
                : (row.getCreatedAt() != null ? row.getCreatedAt() : now.minusSeconds(60));
        LocalDateTime anchorLdt = LocalDateTime.ofInstant(anchor, ZoneOffset.UTC);
        LocalDateTime nowLdt = LocalDateTime.ofInstant(now, ZoneOffset.UTC);

        LocalDateTime cronNext = CronExpression.parse(row.getCronExpression()).next(anchorLdt);
        boolean cronDue = cronNext != null && !nowLdt.isBefore(cronNext);

        boolean retryDue = row.getRetryAfterAt() != null && !now.isBefore(row.getRetryAfterAt());

        return cronDue || retryDue;
    }

    private void recordOutcome(FeedSyncSchedule row, Instant now, boolean failed, String errMsg) {
        if (!failed) {
            row.setLastStatus("OK");
            row.setLastError(null);
            row.setConsecutiveFailures(0);
            row.setRetryAfterAt(null);
            row.setLastRunAt(now);
            row.setUpdatedAt(now);
        } else {
            row.setLastStatus("FAILED");
            row.setLastError(errMsg);
            int n = row.getConsecutiveFailures() + 1;
            row.setConsecutiveFailures(n);
            row.setRetryAfterAt(n < MAX_RETRY_ATTEMPTS
                    ? now.plus(Duration.ofMinutes(backoffMinutes(n)))
                    : null);
            row.setUpdatedAt(now);
            // do NOT advance lastRunAt on failure
        }
        repo.save(row);
    }

    static long backoffMinutes(int n) {
        return 5L * (long) Math.pow(3, n - 1);
    }

    /**
     * Plain (NON-scheduled) delegate — keeps the existing @SpringBootTest wiring/order/isolation
     * coverage green by exercising the real per-feed body. The ONLY scheduled entry point is
     * {@link #tick()}; this method is deliberately not @Scheduled so the durable enable/disable
     * flag and cron in {@code feed_sync_schedule} are the sole gate on automatic feed pulls
     * (a second @Scheduled cron here would fire unconditionally, bypassing the enabled flag).
     */
    public void runFeeds() {
        FeedSyncSchedule row = repo.findById(FeedSyncSchedule.SINGLETON_ID).orElse(null);
        if (row == null) {
            // Fallback: run without recording outcome (old behaviour)
            runFeedsNoRecord();
            return;
        }
        runFeedsOnce(row, clock.instant());
    }

    /** Fallback path when there is no persisted row (migration not yet applied). */
    private void runFeedsNoRecord() {
        try { epss.ingest(); } catch (Exception e) { log.error("EPSS ingest failed: {}", e.toString(), e); }
        try { kev.ingest(); } catch (Exception e) { log.error("KEV ingest failed: {}", e.toString(), e); }
        try {
            if (initialSyncService.isInFlight()) {
                log.info("Scheduled NVD incremental pull skipped — manual sync in flight");
            } else {
                nvd.incrementalPull();
            }
        } catch (Exception e) {
            log.error("NVD incremental pull failed: {}", e.toString(), e);
        }
        riskCacheEvictor.onFeedSyncComplete();
    }
}
