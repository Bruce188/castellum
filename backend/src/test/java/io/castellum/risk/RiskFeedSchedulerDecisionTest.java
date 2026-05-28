package io.castellum.risk;

import io.castellum.admin.InitialSyncService;
import io.castellum.cve.NvdSyncService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

/**
 * Pure-Mockito decision-seam tests for RiskFeedScheduler.checkSchedule(Instant).
 * No @SpringBootTest, no @Scheduled, no wall-clock — mirrors ScanPolicySchedulerTest.
 *
 * Backoff schedule: MAX_RETRY_ATTEMPTS=4, backoffMinutes(n) = 5 * 3^(n-1)
 *   n=1 →  5 min
 *   n=2 → 15 min
 *   n=3 → 45 min
 *   n=4 → 135 min (cap; when consecutiveFailures reaches 4, retryAfterAt = null)
 */
@ExtendWith(MockitoExtension.class)
class RiskFeedSchedulerDecisionTest {

    @Mock FeedSyncScheduleRepository repo;
    @Mock EpssIngestionService epss;
    @Mock KevIngestionService kev;
    @Mock NvdSyncService nvd;
    @Mock InitialSyncService initialSyncService;
    @Mock RiskCacheEvictor riskCacheEvictor;

    // Fixed "now" used in most tests: 2026-05-26T01:02:30Z
    private static final Instant NOW = Instant.parse("2026-05-26T01:02:30Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    /** Build a RiskFeedScheduler using the NEW 7-dep constructor. */
    private RiskFeedScheduler scheduler(Clock clock) {
        return new RiskFeedScheduler(epss, kev, nvd, initialSyncService, riskCacheEvictor, repo, clock);
    }

    /** Helper to build an enabled FeedSyncSchedule row for tests. */
    private FeedSyncSchedule row(boolean enabled, String cron, Instant lastRunAt, Instant createdAt,
                                  Instant retryAfterAt, int consecutiveFailures) {
        FeedSyncSchedule r = new FeedSyncSchedule();
        r.setId(FeedSyncSchedule.SINGLETON_ID);
        r.setEnabled(enabled);
        r.setCronExpression(cron);
        r.setLastRunAt(lastRunAt);
        r.setCreatedAt(createdAt != null ? createdAt : Instant.parse("2026-05-26T00:00:00Z"));
        r.setRetryAfterAt(retryAfterAt);
        r.setConsecutiveFailures(consecutiveFailures);
        return r;
    }

    // -------------------------------------------------------------------------
    // Case 1: fires when due + enabled
    // -------------------------------------------------------------------------
    @Test
    void checkSchedule_firesWhenDueAndEnabled_invokesAllFeedsInOrder_savesOkStatus() throws Exception {
        // Cron "0 * * * * *" = second 0 of every minute.
        // lastRunAt=01:00:00 → next=01:01:00. now=01:02:30 → clearly due.
        FeedSyncSchedule r = row(true, "0 * * * * *",
                Instant.parse("2026-05-26T01:00:00Z"),
                Instant.parse("2026-05-26T00:00:00Z"),
                null, 0);
        when(repo.findById(FeedSyncSchedule.SINGLETON_ID)).thenReturn(Optional.of(r));
        when(initialSyncService.isInFlight()).thenReturn(false);

        RiskFeedScheduler sched = scheduler(CLOCK);
        sched.checkSchedule(NOW);

        // All three feeds invoked in order
        InOrder inOrder = inOrder(epss, kev, nvd);
        inOrder.verify(epss).ingest();
        inOrder.verify(kev).ingest();
        inOrder.verify(nvd).incrementalPull();

        // Cache eviction called
        verify(riskCacheEvictor).onFeedSyncComplete();

        // repo.save called with OK status, consecutiveFailures=0, retryAfterAt=null, lastRunAt advanced
        verify(repo).save(argThat(saved ->
                "OK".equals(saved.getLastStatus())
                && saved.getConsecutiveFailures() == 0
                && saved.getRetryAfterAt() == null
                && saved.getLastRunAt() != null
                && saved.getLastError() == null
        ));
    }

    // -------------------------------------------------------------------------
    // Case 2: does NOT fire when disabled
    // -------------------------------------------------------------------------
    @Test
    void checkSchedule_doesNotFireWhenDisabled() throws Exception {
        FeedSyncSchedule r = row(false, "0 * * * * *",
                Instant.parse("2026-05-26T01:00:00Z"),
                Instant.parse("2026-05-26T00:00:00Z"),
                null, 0);
        when(repo.findById(FeedSyncSchedule.SINGLETON_ID)).thenReturn(Optional.of(r));

        RiskFeedScheduler sched = scheduler(CLOCK);
        sched.checkSchedule(NOW);

        verify(epss, never()).ingest();
        verify(kev, never()).ingest();
        verify(nvd, never()).incrementalPull();
        verify(repo, never()).save(any());
    }

    // -------------------------------------------------------------------------
    // Case 3: does NOT fire when cron not yet due
    // -------------------------------------------------------------------------
    @Test
    void checkSchedule_doesNotFireWhenCronNotDue() throws Exception {
        // "0 0 * * * *" = top of every hour. lastRunAt=01:00:00 → next=02:00:00.
        // now=01:02:30 → not yet due, no retryAfterAt.
        FeedSyncSchedule r = row(true, "0 0 * * * *",
                Instant.parse("2026-05-26T01:00:00Z"),
                Instant.parse("2026-05-26T00:00:00Z"),
                null, 0);
        when(repo.findById(FeedSyncSchedule.SINGLETON_ID)).thenReturn(Optional.of(r));

        RiskFeedScheduler sched = scheduler(CLOCK);
        sched.checkSchedule(NOW);

        verify(epss, never()).ingest();
        verify(kev, never()).ingest();
        verify(nvd, never()).incrementalPull();
        verify(repo, never()).save(any());
    }

    // -------------------------------------------------------------------------
    // Case 4a: does NOT fire when within backoff window
    // -------------------------------------------------------------------------
    @Test
    void checkSchedule_doesNotFireWhenRetryAfterAtInFuture() throws Exception {
        // retryAfterAt is in the future → still in backoff window → no fire
        Instant retryAfterAt = Instant.parse("2026-05-26T02:00:00Z"); // > NOW
        FeedSyncSchedule r = row(true, "0 0 * * * *",
                Instant.parse("2026-05-26T01:00:00Z"),
                Instant.parse("2026-05-26T00:00:00Z"),
                retryAfterAt, 1);
        when(repo.findById(FeedSyncSchedule.SINGLETON_ID)).thenReturn(Optional.of(r));

        RiskFeedScheduler sched = scheduler(CLOCK);
        sched.checkSchedule(NOW); // cron not due, retry not due

        verify(epss, never()).ingest();
        verify(kev, never()).ingest();
        verify(nvd, never()).incrementalPull();
        verify(repo, never()).save(any());
    }

    // -------------------------------------------------------------------------
    // Case 4b: retry-due fires even when cron not otherwise due
    // -------------------------------------------------------------------------
    @Test
    void checkSchedule_firesWhenRetryAfterAtElapsed_evenIfCronNotDue() throws Exception {
        // retryAfterAt = 01:00:00 <= now=01:02:30 → retryDue=true → fire
        // cron "0 0 * * * *" not due (next=02:00:00)
        Instant retryAfterAt = Instant.parse("2026-05-26T01:00:00Z");
        FeedSyncSchedule r = row(true, "0 0 * * * *",
                Instant.parse("2026-05-25T23:00:00Z"),
                Instant.parse("2026-05-26T00:00:00Z"),
                retryAfterAt, 1);
        when(repo.findById(FeedSyncSchedule.SINGLETON_ID)).thenReturn(Optional.of(r));
        when(initialSyncService.isInFlight()).thenReturn(false);

        RiskFeedScheduler sched = scheduler(CLOCK);
        sched.checkSchedule(NOW);

        verify(epss).ingest();
        verify(kev).ingest();
        verify(nvd).incrementalPull();
        verify(repo).save(any());
    }

    // -------------------------------------------------------------------------
    // Case 5: success resets failure state
    // -------------------------------------------------------------------------
    @Test
    void checkSchedule_successResetsFailureState() throws Exception {
        FeedSyncSchedule r = row(true, "0 * * * * *",
                Instant.parse("2026-05-26T01:00:00Z"),
                Instant.parse("2026-05-26T00:00:00Z"),
                Instant.parse("2026-05-26T01:00:00Z"), // retryDue (elapsed)
                2);
        r.setLastStatus("FAILED");
        r.setLastError("previous error");
        when(repo.findById(FeedSyncSchedule.SINGLETON_ID)).thenReturn(Optional.of(r));
        when(initialSyncService.isInFlight()).thenReturn(false);

        RiskFeedScheduler sched = scheduler(CLOCK);
        sched.checkSchedule(NOW);

        verify(repo).save(argThat(saved ->
                "OK".equals(saved.getLastStatus())
                && saved.getConsecutiveFailures() == 0
                && saved.getRetryAfterAt() == null
                && saved.getLastError() == null
                && saved.getLastRunAt() != null
        ));
    }

    // -------------------------------------------------------------------------
    // Case 6a: failure increments consecutiveFailures + sets backoff (n=1 → 5 min)
    //          and does NOT advance lastRunAt
    // -------------------------------------------------------------------------
    @Test
    void checkSchedule_firstFailure_setsConsecutiveFailures1_andBackoff5min() throws Exception {
        Instant originalLastRunAt = Instant.parse("2026-05-26T01:00:00Z");
        FeedSyncSchedule r = row(true, "0 * * * * *",
                originalLastRunAt,
                Instant.parse("2026-05-26T00:00:00Z"),
                null, 0);
        when(repo.findById(FeedSyncSchedule.SINGLETON_ID)).thenReturn(Optional.of(r));
        when(initialSyncService.isInFlight()).thenReturn(false);
        when(epss.ingest()).thenThrow(new IOException("boom"));

        RiskFeedScheduler sched = scheduler(CLOCK);
        sched.checkSchedule(NOW);

        Instant expectedRetry = NOW.plus(Duration.ofMinutes(5)); // n=1 → 5*3^0 = 5
        verify(repo).save(argThat(saved ->
                "FAILED".equals(saved.getLastStatus())
                && saved.getConsecutiveFailures() == 1
                && expectedRetry.equals(saved.getRetryAfterAt())
                && saved.getLastError() != null && saved.getLastError().contains("boom")
                && originalLastRunAt.equals(saved.getLastRunAt()) // NOT advanced
        ));
    }

    // -------------------------------------------------------------------------
    // Case 6b: second failure → consecutiveFailures=2, backoff=15 min
    // -------------------------------------------------------------------------
    @Test
    void checkSchedule_secondFailure_setsConsecutiveFailures2_andBackoff15min() throws Exception {
        Instant originalLastRunAt = Instant.parse("2026-05-25T23:00:00Z");
        // retryAfterAt elapsed so it fires
        FeedSyncSchedule r = row(true, "0 0 * * * *",
                originalLastRunAt,
                Instant.parse("2026-05-26T00:00:00Z"),
                Instant.parse("2026-05-26T01:00:00Z"), // elapsed → retryDue
                1); // existing consecutiveFailures=1
        when(repo.findById(FeedSyncSchedule.SINGLETON_ID)).thenReturn(Optional.of(r));
        when(initialSyncService.isInFlight()).thenReturn(false);
        when(kev.ingest()).thenThrow(new IOException("kev-boom"));

        RiskFeedScheduler sched = scheduler(CLOCK);
        sched.checkSchedule(NOW);

        Instant expectedRetry = NOW.plus(Duration.ofMinutes(15)); // n=2 → 5*3^1 = 15
        verify(repo).save(argThat(saved ->
                "FAILED".equals(saved.getLastStatus())
                && saved.getConsecutiveFailures() == 2
                && expectedRetry.equals(saved.getRetryAfterAt())
                && originalLastRunAt.equals(saved.getLastRunAt()) // NOT advanced on failure
        ));
    }

    // -------------------------------------------------------------------------
    // Case 6c: at MAX_RETRY_ATTEMPTS (4) → retryAfterAt = null (stop retrying)
    // -------------------------------------------------------------------------
    @Test
    void checkSchedule_atMaxRetryAttempts_setsRetryAfterAtNull() throws Exception {
        // n=4 (consecutiveFailures was 3 before this run → becomes 4 = MAX_RETRY_ATTEMPTS)
        FeedSyncSchedule r = row(true, "0 * * * * *",
                Instant.parse("2026-05-26T01:00:00Z"),
                Instant.parse("2026-05-26T00:00:00Z"),
                null, 3); // going to become 4
        when(repo.findById(FeedSyncSchedule.SINGLETON_ID)).thenReturn(Optional.of(r));
        when(initialSyncService.isInFlight()).thenReturn(false);
        when(nvd.incrementalPull()).thenThrow(new IOException("nvd-fail"));

        RiskFeedScheduler sched = scheduler(CLOCK);
        sched.checkSchedule(NOW);

        verify(repo).save(argThat(saved ->
                "FAILED".equals(saved.getLastStatus())
                && saved.getConsecutiveFailures() == 4
                && saved.getRetryAfterAt() == null // at cap → null
        ));
    }

    // -------------------------------------------------------------------------
    // Case 7: fetch exception does NOT crash tick; cache eviction still runs
    // -------------------------------------------------------------------------
    @Test
    void checkSchedule_fetchException_doesNotPropagateOutOfCheckSchedule() throws Exception {
        FeedSyncSchedule r = row(true, "0 * * * * *",
                Instant.parse("2026-05-26T01:00:00Z"),
                Instant.parse("2026-05-26T00:00:00Z"),
                null, 0);
        when(repo.findById(FeedSyncSchedule.SINGLETON_ID)).thenReturn(Optional.of(r));
        when(initialSyncService.isInFlight()).thenReturn(false);
        when(nvd.incrementalPull()).thenThrow(new IOException("nvd-boom"));

        RiskFeedScheduler sched = scheduler(CLOCK);
        assertThatCode(() -> sched.checkSchedule(NOW)).doesNotThrowAnyException();

        // EPSS and KEV still ran (per-feed isolation preserved)
        verify(epss).ingest();
        verify(kev).ingest();
        // Cache eviction still happens after per-feed body (mirrors existing runFeeds isolation)
        verify(riskCacheEvictor).onFeedSyncComplete();
        // Failure recorded
        verify(repo).save(argThat(saved -> "FAILED".equals(saved.getLastStatus())));
    }

    // -------------------------------------------------------------------------
    // Case 8: malformed cron does NOT crash the tick (outer wrapper)
    // -------------------------------------------------------------------------
    @Test
    void tick_malformedCron_doesNotCrash_noIngestNoSave() throws Exception {
        FeedSyncSchedule r = row(true, "not-a-cron",
                Instant.parse("2026-05-26T01:00:00Z"),
                Instant.parse("2026-05-26T00:00:00Z"),
                null, 0);
        when(repo.findById(FeedSyncSchedule.SINGLETON_ID)).thenReturn(Optional.of(r));

        // Call tick() to exercise the outer try/catch(RuntimeException) wrapper
        RiskFeedScheduler sched = scheduler(CLOCK);
        assertThatCode(sched::tick).doesNotThrowAnyException();

        verify(epss, never()).ingest();
        verify(kev, never()).ingest();
        verify(nvd, never()).incrementalPull();
        verify(repo, never()).save(any());
    }

    // -------------------------------------------------------------------------
    // Case 9: skips fire while manual sync in flight
    // -------------------------------------------------------------------------
    @Test
    void checkSchedule_skipsWhenManualSyncInFlight() throws Exception {
        FeedSyncSchedule r = row(true, "0 * * * * *",
                Instant.parse("2026-05-26T01:00:00Z"),
                Instant.parse("2026-05-26T00:00:00Z"),
                null, 0);
        when(repo.findById(FeedSyncSchedule.SINGLETON_ID)).thenReturn(Optional.of(r));
        when(initialSyncService.isInFlight()).thenReturn(true);

        RiskFeedScheduler sched = scheduler(CLOCK);
        sched.checkSchedule(NOW);

        verify(epss, never()).ingest();
        verify(kev, never()).ingest();
        verify(nvd, never()).incrementalPull();
        verify(repo, never()).save(any());
    }
}
