package io.castellum.admin;

import io.castellum.cve.NvdSyncService;
import io.castellum.risk.EpssIngestionService;
import io.castellum.risk.KevIngestionService;
import io.castellum.web.dto.InitialSyncRequest;
import io.castellum.web.dto.InitialSyncResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.io.IOException;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class InitialSyncServiceTest {

    private NvdSyncService nvdSyncService;
    private EpssIngestionService epssIngestionService;
    private KevIngestionService kevIngestionService;
    private InitialSyncService service;

    /**
     * Uses a synchronous executor so Runnable::run happens inline,
     * making async assertions deterministic.
     */
    private ThreadPoolTaskExecutor syncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(1);
        executor.setQueueCapacity(0);
        executor.setThreadNamePrefix("test-sync-");
        // Override with a same-thread executor for deterministic tests
        executor.initialize();
        return executor;
    }

    @BeforeEach
    void setUp() {
        nvdSyncService = mock(NvdSyncService.class);
        epssIngestionService = mock(EpssIngestionService.class);
        kevIngestionService = mock(KevIngestionService.class);

        // Use a ThreadPoolTaskExecutor that executes synchronously
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(1);
        executor.setQueueCapacity(10);
        executor.setThreadNamePrefix("test-");
        executor.initialize();

        service = new InitialSyncService(executor, nvdSyncService, epssIngestionService,
            kevIngestionService);
    }

    // ── Task A.3 CAS contract tests ────────────────────────────────────────────

    @Test
    void firstTrigger_returnsStarted_withNonNullStartedAt() {
        InitialSyncResponse resp = service.trigger(InitialSyncRequest.defaults(), "admin");
        assertEquals("started", resp.status());
        assertNotNull(resp.startedAt(), "startedAt must not be null on first trigger");
    }

    @Test
    void secondTriggerWhileInFlight_returnsAlreadyRunning_withSameStartedAt() throws Exception {
        // Hold the background thread so the second trigger fires while in-flight
        java.util.concurrent.CountDownLatch hold = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch running = new java.util.concurrent.CountDownLatch(1);

        doAnswer(inv -> {
            running.countDown();
            hold.await();
            return null;
        }).when(nvdSyncService).bulkPull(any(), any());

        InitialSyncResponse first = service.trigger(InitialSyncRequest.defaults(), "admin");
        running.await(5, java.util.concurrent.TimeUnit.SECONDS);

        InitialSyncResponse second = service.trigger(InitialSyncRequest.defaults(), "admin");
        hold.countDown();

        assertEquals("started", first.status());
        assertEquals("already-running", second.status());
        assertEquals(first.startedAt(), second.startedAt(), "startedAt must be identical for in-flight guard");
    }

    // ── Task B.1 orchestration tests ──────────────────────────────────────────

    @Test
    void trigger_invokesNvdBulkPull_withEpochSince() throws Exception {
        service.trigger(InitialSyncRequest.defaults(), "admin");
        // Allow the async task to complete
        Thread.sleep(200);

        verify(nvdSyncService).bulkPull(eq(Instant.EPOCH), any(Instant.class));
    }

    @Test
    void trigger_epssAndKevStillInvokedEvenIfNvdFails() throws Exception {
        doThrow(new IOException("NVD down")).when(nvdSyncService).bulkPull(any(), any());

        service.trigger(InitialSyncRequest.defaults(), "admin");
        Thread.sleep(200);

        verify(epssIngestionService).ingest();
        verify(kevIngestionService).ingest();
    }

    @Test
    void trigger_kevStillInvokedEvenIfEpssFails() throws Exception {
        doThrow(new IOException("EPSS down")).when(epssIngestionService).ingest();

        service.trigger(InitialSyncRequest.defaults(), "admin");
        Thread.sleep(200);

        verify(kevIngestionService).ingest();
    }

    @Test
    void trigger_afterRunCompletes_allowsNewSync() throws Exception {
        service.trigger(InitialSyncRequest.defaults(), "admin");
        Thread.sleep(200); // wait for background task to finish and clear inFlight

        InitialSyncResponse second = service.trigger(InitialSyncRequest.defaults(), "admin");
        assertEquals("started", second.status(), "inFlight must be cleared after completion");
    }

    @Test
    void trigger_explicitWindow_passesExactInstants() throws Exception {
        Instant since = Instant.parse("2024-01-01T00:00:00Z");
        Instant until = Instant.parse("2025-01-01T00:00:00Z");
        InitialSyncRequest req = new InitialSyncRequest(since, until);

        service.trigger(req, "admin");
        Thread.sleep(200);

        verify(nvdSyncService).bulkPull(eq(since), eq(until));
    }
}
