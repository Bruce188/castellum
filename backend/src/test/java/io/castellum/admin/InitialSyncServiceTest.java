package io.castellum.admin;

import io.castellum.audit.AuditFilter;
import io.castellum.audit.AuditLog;
import io.castellum.audit.AuditLogRepository;
import io.castellum.audit.AuditQuerySpecifications;
import io.castellum.audit.AuditService;
import io.castellum.cve.NvdSyncService;
import io.castellum.risk.EpssIngestionService;
import io.castellum.risk.KevIngestionService;
import io.castellum.web.dto.InitialSyncRequest;
import io.castellum.web.dto.InitialSyncResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class InitialSyncServiceTest {

    private NvdSyncService nvdSyncService;
    private EpssIngestionService epssIngestionService;
    private KevIngestionService kevIngestionService;
    private AuditService auditService;
    private AuditLogRepository auditLogRepository;
    private io.castellum.risk.RiskCacheEvictor riskCacheEvictor;
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
        auditService = mock(AuditService.class);
        auditLogRepository = mock(AuditLogRepository.class);
        riskCacheEvictor = mock(io.castellum.risk.RiskCacheEvictor.class);

        // Use a ThreadPoolTaskExecutor that executes synchronously
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(1);
        executor.setQueueCapacity(10);
        executor.setThreadNamePrefix("test-");
        executor.initialize();

        // Default: audit repo returns empty pages (no completed events, no triggered events)
        when(auditLogRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(Page.empty());

        service = new InitialSyncService(executor, nvdSyncService, epssIngestionService,
            kevIngestionService, auditService, auditLogRepository, riskCacheEvictor);
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
        InitialSyncRequest req = new InitialSyncRequest(since, until, false);

        service.trigger(req, "admin");
        Thread.sleep(200);

        verify(nvdSyncService).bulkPull(eq(since), eq(until));
    }

    // ── Task 1 new tests: terminal audit event + durable reconstruction ───────

    @Test
    void runSync_onSuccess_emitsInitialSyncCompletedEvent_withOkTrue() throws Exception {
        service.trigger(InitialSyncRequest.defaults(), "admin");
        Thread.sleep(200);

        verify(auditService).recordEvent(
                anyString(),
                eq("INITIAL_SYNC_COMPLETED"),
                eq("initial-sync"),
                eq("global"),
                argThat(payload -> {
                    if (!(payload instanceof Map)) return false;
                    @SuppressWarnings("unchecked")
                    Map<String, Object> m = (Map<String, Object>) payload;
                    return Boolean.TRUE.equals(m.get("ok"))
                            && m.get("failedFeeds") instanceof List
                            && ((List<?>) m.get("failedFeeds")).isEmpty()
                            && m.get("lastError") == null;
                })
        );
    }

    @Test
    void runSync_onSuccess_setsLastCompletedAt_clearsLastError() throws Exception {
        service.trigger(InitialSyncRequest.defaults(), "admin");
        Thread.sleep(200);

        assertNotNull(service.getLastCompletedAt(), "lastCompletedAt must be set after successful run");
        assertNull(service.getLastError(), "lastError must be null after successful run");
    }

    @Test
    void runSync_whenKevFails_emitsCompletedEvent_okFalse_withKevInFailedFeeds_andLastError()
            throws Exception {
        doThrow(new IOException("KEV down")).when(kevIngestionService).ingest();

        service.trigger(InitialSyncRequest.defaults(), "admin");
        Thread.sleep(200);

        // per-feed isolation: EPSS still ran
        verify(epssIngestionService).ingest();

        verify(auditService).recordEvent(
                anyString(),
                eq("INITIAL_SYNC_COMPLETED"),
                eq("initial-sync"),
                eq("global"),
                argThat(payload -> {
                    if (!(payload instanceof Map)) return false;
                    @SuppressWarnings("unchecked")
                    Map<String, Object> m = (Map<String, Object>) payload;
                    if (Boolean.TRUE.equals(m.get("ok"))) return false;
                    List<?> failed = (List<?>) m.get("failedFeeds");
                    if (failed == null || failed.isEmpty()) return false;
                    String lastErr = (String) m.get("lastError");
                    return lastErr != null && lastErr.contains("KEV down");
                })
        );

        assertNotNull(service.getLastError());
        assertTrue(service.getLastError().contains("KEV down"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void syncStatus_afterRestart_reconstructsLastCompletedFromAudit() throws Exception {
        // Simulate restart: fresh service instance with empty in-memory state
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(1);
        executor.setQueueCapacity(10);
        executor.setThreadNamePrefix("test-restart-");
        executor.initialize();

        AuditLogRepository freshRepo = mock(AuditLogRepository.class);
        AuditService freshAuditService = mock(AuditService.class);

        Instant completedTs = Instant.parse("2026-05-20T10:00:00Z");
        AuditLog completedRow = new AuditLog(
                completedTs, "system", "INITIAL_SYNC_COMPLETED",
                "initial-sync", "global",
                "{\"ok\":true,\"failedFeeds\":[],\"lastError\":null}");

        Page<AuditLog> completedPage = new PageImpl<>(List.of(completedRow));
        // First call (COMPLETED query) returns the completed row
        when(freshRepo.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(completedPage);

        InitialSyncService freshService = new InitialSyncService(
                executor, nvdSyncService, epssIngestionService, kevIngestionService,
                freshAuditService, freshRepo, mock(io.castellum.risk.RiskCacheEvictor.class));

        assertEquals(completedTs, freshService.getLastCompletedAt(),
                "getLastCompletedAt must reconstruct from audit row after restart");
        assertNull(freshService.getLastError(),
                "getLastError must be null when audit payload says ok=true");
    }

    @Test
    @SuppressWarnings("unchecked")
    void syncStatus_afterRestart_reconstructsFailedRun() throws Exception {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(1);
        executor.setQueueCapacity(10);
        executor.setThreadNamePrefix("test-restart2-");
        executor.initialize();

        AuditLogRepository freshRepo = mock(AuditLogRepository.class);
        AuditService freshAuditService = mock(AuditService.class);

        Instant completedTs = Instant.parse("2026-05-19T08:00:00Z");
        AuditLog failedRow = new AuditLog(
                completedTs, "system", "INITIAL_SYNC_COMPLETED",
                "initial-sync", "global",
                "{\"ok\":false,\"failedFeeds\":[\"NVD\"],\"lastError\":\"NVD down\"}");

        Page<AuditLog> failedPage = new PageImpl<>(List.of(failedRow));
        when(freshRepo.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(failedPage);

        InitialSyncService freshService = new InitialSyncService(
                executor, nvdSyncService, epssIngestionService, kevIngestionService,
                freshAuditService, freshRepo, mock(io.castellum.risk.RiskCacheEvictor.class));

        assertNotNull(freshService.getLastError());
        assertTrue(freshService.getLastError().contains("NVD down"),
                "getLastError must reconstruct from failed audit payload");
    }

    @Test
    @SuppressWarnings("unchecked")
    void syncStatus_afterRestart_triggeredButNoCompletion_reportsInterrupted() throws Exception {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(1);
        executor.setQueueCapacity(10);
        executor.setThreadNamePrefix("test-interrupted-");
        executor.initialize();

        AuditLogRepository freshRepo = mock(AuditLogRepository.class);
        AuditService freshAuditService = mock(AuditService.class);

        // COMPLETED query returns empty; TRIGGERED query returns a row
        AuditLog triggeredRow = new AuditLog(
                Instant.parse("2026-05-18T06:00:00Z"), "admin", "INITIAL_SYNC_TRIGGERED",
                "initial-sync", "global", "{\"since\":\"1970-01-01T00:00:00Z\"}");
        Page<AuditLog> emptyPage = new PageImpl<>(Collections.emptyList());
        Page<AuditLog> triggeredPage = new PageImpl<>(List.of(triggeredRow));

        when(freshRepo.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(emptyPage)    // first call: COMPLETED query → empty
                .thenReturn(triggeredPage); // second call: TRIGGERED query → has a row

        InitialSyncService freshService = new InitialSyncService(
                executor, nvdSyncService, epssIngestionService, kevIngestionService,
                freshAuditService, freshRepo, mock(io.castellum.risk.RiskCacheEvictor.class));

        assertEquals("interrupted", freshService.getLastError(),
                "lastError must be 'interrupted' when triggered but no completion exists");
        assertNull(freshService.getLastCompletedAt(),
                "lastCompletedAt must be null when sync was interrupted");
    }

    // ── AC1/AC3: full-backfill routing tests ──────────────────────────────────

    /**
     * AC1 (core regression): when fullBackfill=true AND the table is non-empty,
     * the service must call {@code fullBackfillPull()}, NOT {@code bulkPull()},
     * so the incremental {@code findMaxLastModified} short-circuit is bypassed.
     */
    @Test
    void trigger_fullBackfill_callsFullBackfillPull_notBulkPull() throws Exception {
        InitialSyncRequest req = new InitialSyncRequest(null, null, true);

        service.trigger(req, "admin");
        Thread.sleep(200);

        verify(nvdSyncService).fullBackfillPull();
        verify(nvdSyncService, never()).bulkPull(any(), any());
        verify(nvdSyncService, never()).incrementalPull();
    }

    /**
     * AC3: when fullBackfill=false (default), the service must use the regular
     * bulkPull path — the force flag must not change incremental behaviour.
     */
    @Test
    void trigger_noFullBackfill_callsBulkPull_asUsual() throws Exception {
        InitialSyncRequest req = InitialSyncRequest.defaults(); // fullBackfill=false

        service.trigger(req, "admin");
        Thread.sleep(200);

        verify(nvdSyncService).bulkPull(eq(Instant.EPOCH), any(Instant.class));
        verify(nvdSyncService, never()).fullBackfillPull();
    }

    /**
     * AC1: even when fullBackfill pull throws, EPSS+KEV still run (resilience contract).
     */
    @Test
    void trigger_fullBackfill_epssAndKevStillRunEvenOnNvdFailure() throws Exception {
        doThrow(new java.io.IOException("NVD down"))
            .when(nvdSyncService).fullBackfillPull();

        InitialSyncRequest req = new InitialSyncRequest(null, null, true);
        service.trigger(req, "admin");
        Thread.sleep(200);

        verify(epssIngestionService).ingest();
        verify(kevIngestionService).ingest();
    }
}
