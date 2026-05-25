package io.castellum.admin;

import io.castellum.cve.NvdSyncService;
import io.castellum.risk.EpssIngestionService;
import io.castellum.risk.KevIngestionService;
import io.castellum.web.dto.InitialSyncRequest;
import io.castellum.web.dto.InitialSyncResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Orchestrates the one-click initial data-sync background job.
 *
 * <p>An {@code AtomicBoolean inFlight} gate ensures at most one sync runs at a time.
 * Concurrent callers receive a 202 with {@code status:"already-running"} and the
 * {@code startedAt} timestamp of the in-flight job.
 *
 * <p>The background task invokes NVD bulk pull, EPSS ingest, and KEV ingest
 * <em>sequentially</em> with per-feed failure isolation: a failure in one feed does NOT
 * prevent the remaining feeds from running.  The {@code finally} block always clears
 * {@code inFlight} so future syncs are not permanently locked out.
 */
@Service
public class InitialSyncService {

    private static final Logger log = LoggerFactory.getLogger(InitialSyncService.class);

    private final ThreadPoolTaskExecutor executor;
    private final NvdSyncService nvdSyncService;
    private final EpssIngestionService epssIngestionService;
    private final KevIngestionService kevIngestionService;

    private final AtomicBoolean inFlight = new AtomicBoolean(false);
    private volatile Instant startedAt;

    public InitialSyncService(
            @Qualifier("initialSyncTaskExecutor") ThreadPoolTaskExecutor executor,
            NvdSyncService nvdSyncService,
            EpssIngestionService epssIngestionService,
            KevIngestionService kevIngestionService) {
        this.executor = executor;
        this.nvdSyncService = nvdSyncService;
        this.epssIngestionService = epssIngestionService;
        this.kevIngestionService = kevIngestionService;
    }

    /**
     * Triggers the initial sync if none is currently running.
     *
     * <p>Returns immediately with a {@link InitialSyncResponse} indicating whether
     * a new sync was started or one was already in flight.
     */
    public InitialSyncResponse trigger(InitialSyncRequest req, String actor) {
        if (inFlight.compareAndSet(false, true)) {
            startedAt = Instant.now();
            executor.submit(() -> runSync(req, actor));
            return new InitialSyncResponse("started", startedAt);
        } else {
            return new InitialSyncResponse("already-running", startedAt);
        }
    }

    private void runSync(InitialSyncRequest req, String actor) {
        try {
            runNvd(req);
            runEpss();
            runKev();
        } finally {
            inFlight.set(false);
        }
    }

    private void runNvd(InitialSyncRequest req) {
        try {
            nvdSyncService.bulkPull(req.effectiveSince(), req.effectiveUntil());
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            log.warn("Initial sync: NVD bulk pull failed — EPSS+KEV will still run: {}", e.getMessage(), e);
        }
    }

    private void runEpss() {
        try {
            epssIngestionService.ingest();
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            log.warn("Initial sync: EPSS ingest failed — KEV will still run: {}", e.getMessage(), e);
        }
    }

    private void runKev() {
        try {
            kevIngestionService.ingest();
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            log.warn("Initial sync: KEV ingest failed: {}", e.getMessage(), e);
        }
    }
}
