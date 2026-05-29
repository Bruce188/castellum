package io.castellum.cve;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.context.ConfigurableApplicationContext;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NvdSyncRunnerTest {

    @Mock
    NvdSyncService syncService;

    @Mock
    ConfigurableApplicationContext ctx;

    NvdSyncRunner runner;

    /** Captures exit codes passed to the injectable exit handler. */
    List<Integer> capturedExitCodes;

    @BeforeEach
    void setUp() {
        capturedExitCodes = new ArrayList<>();
        runner = new NvdSyncRunner(syncService, ctx);
        runner.exitHandler = capturedExitCodes::add;
    }

    @Test
    void runner_invokesBulkPull_whenSinceProvided() throws Exception {
        NvdSyncService.SyncSummary summary = new NvdSyncService.SyncSummary(1, 1, 3, 5);
        when(syncService.bulkPull(any(Instant.class), any(Instant.class))).thenReturn(summary);

        runner.run(new DefaultApplicationArguments("--nvd-sync", "--since=2026-04-01T00:00:00Z"));

        verify(syncService, times(1)).bulkPull(eq(Instant.parse("2026-04-01T00:00:00Z")), any(Instant.class));
        verify(syncService, never()).incrementalPull();
    }

    @Test
    void runner_invokesIncrementalPull_whenNoSinceProvided() throws Exception {
        NvdSyncService.SyncSummary summary = new NvdSyncService.SyncSummary(1, 1, 3, 5);
        when(syncService.incrementalPull()).thenReturn(summary);

        runner.run(new DefaultApplicationArguments("--nvd-sync"));

        verify(syncService, times(1)).incrementalPull();
        verify(syncService, never()).bulkPull(any(), any());
    }

    @Test
    void runner_isNoOp_whenSyncFlagAbsent() throws Exception {
        runner.run(new DefaultApplicationArguments());

        verifyNoInteractions(syncService);
        // Server boot path: exitHandler must NOT be called when --nvd-sync is absent.
        assertTrue(capturedExitCodes.isEmpty(), "exitHandler must not fire on normal server boot");
    }

    @Test
    void runner_exitsWithCode1_onIOException() throws Exception {
        when(syncService.bulkPull(any(Instant.class), any(Instant.class)))
            .thenThrow(new IOException("NVD network error"));

        // IOException is now caught; exitHandler(1) fires instead of re-throwing.
        runner.run(new DefaultApplicationArguments("--nvd-sync", "--since=2026-04-01T00:00:00Z"));

        assertEquals(List.of(1), capturedExitCodes);
    }

    @Test
    void runner_useUntilFromArgWhenProvided() throws Exception {
        NvdSyncService.SyncSummary summary = new NvdSyncService.SyncSummary(1, 1, 3, 5);
        when(syncService.bulkPull(any(Instant.class), any(Instant.class))).thenReturn(summary);

        runner.run(new DefaultApplicationArguments(
            "--nvd-sync",
            "--since=2026-04-01T00:00:00Z",
            "--until=2026-04-15T00:00:00Z"));

        verify(syncService, times(1)).bulkPull(
            eq(Instant.parse("2026-04-01T00:00:00Z")),
            eq(Instant.parse("2026-04-15T00:00:00Z")));
    }

    @Test
    void invalidSinceArg_throwsIllegalArgumentException() {
        var args = new DefaultApplicationArguments("--nvd-sync", "--since=not-a-date");

        var ex = assertThrows(
            IllegalArgumentException.class,
            () -> runner.run(args)
        );

        assertTrue(
            ex.getMessage().contains("not-a-date"),
            "message must echo offending value, was: " + ex.getMessage()
        );
        assertTrue(
            ex.getCause() instanceof java.time.format.DateTimeParseException,
            "cause must be DateTimeParseException, was: " + ex.getCause()
        );
    }

    // ── AC3: --full flag ──────────────────────────────────────────────────────

    /**
     * AC3: {@code --full} flag must call {@code fullBackfillPull()}, not
     * {@code incrementalPull()} or {@code bulkPull()}.
     * This is the CLI fix for the silent-incremental footgun.
     */
    @Test
    void runner_fullFlag_invokesFullBackfillPull() throws Exception {
        NvdSyncService.SyncSummary summary = new NvdSyncService.SyncSummary(73, 800, 250000, 3000);
        when(syncService.fullBackfillPull()).thenReturn(summary);

        runner.run(new DefaultApplicationArguments("--nvd-sync", "--full"));

        verify(syncService, times(1)).fullBackfillPull();
        verify(syncService, never()).incrementalPull();
        verify(syncService, never()).bulkPull(any(), any());
    }

    /**
     * AC3: {@code --full} takes priority even when {@code --since} is also provided
     * (explicit full wins over conflicting --since).
     */
    @Test
    void runner_fullFlagOverridesSince() throws Exception {
        NvdSyncService.SyncSummary summary = new NvdSyncService.SyncSummary(73, 800, 250000, 3000);
        when(syncService.fullBackfillPull()).thenReturn(summary);

        runner.run(new DefaultApplicationArguments(
            "--nvd-sync", "--full", "--since=2026-04-01T00:00:00Z"));

        verify(syncService, times(1)).fullBackfillPull();
        verify(syncService, never()).bulkPull(any(), any());
        verify(syncService, never()).incrementalPull();
    }

    // ── Exit-handler contract ────────────────────────────────────────────────

    /**
     * CLI one-shot: {@code --nvd-sync --full} triggers exitHandler(0) after
     * {@code fullBackfillPull()} succeeds.
     */
    @Test
    void exitHandler_calledWithZero_afterSuccessfulFullSync() throws Exception {
        NvdSyncService.SyncSummary summary = new NvdSyncService.SyncSummary(73, 800, 250000, 3000);
        when(syncService.fullBackfillPull()).thenReturn(summary);

        runner.run(new DefaultApplicationArguments("--nvd-sync", "--full"));

        assertEquals(List.of(0), capturedExitCodes,
            "exitHandler must be called with 0 on successful sync");
    }

    /**
     * Server boot path: when {@code --nvd-sync} is absent the exitHandler must
     * never fire — the JVM stays alive for normal web-server operation.
     */
    @Test
    void exitHandler_notCalled_whenNvdSyncFlagAbsent() throws Exception {
        runner.run(new DefaultApplicationArguments("--server.port=8081"));

        assertTrue(capturedExitCodes.isEmpty(),
            "exitHandler must not fire when --nvd-sync is absent (normal server boot)");
        verifyNoInteractions(syncService);
    }

    /**
     * CLI one-shot failure: an IOException from the sync service must cause
     * exitHandler(1) to fire (not re-throw), so the JVM exits with a non-zero
     * status that CI / shell callers can detect.
     */
    @Test
    void exitHandler_calledWithOne_onSyncIOException() throws Exception {
        when(syncService.fullBackfillPull()).thenThrow(new IOException("timeout"));

        runner.run(new DefaultApplicationArguments("--nvd-sync", "--full"));

        assertEquals(List.of(1), capturedExitCodes,
            "exitHandler must be called with 1 on sync IOException");
    }
}
