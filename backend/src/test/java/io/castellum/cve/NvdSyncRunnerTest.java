package io.castellum.cve;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.DefaultApplicationArguments;

import java.io.IOException;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NvdSyncRunnerTest {

    @Mock
    NvdSyncService syncService;

    NvdSyncRunner runner;

    @BeforeEach
    void setUp() {
        runner = new NvdSyncRunner(syncService);
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
    }

    @Test
    void runner_propagatesIOException_byThrowing() throws Exception {
        when(syncService.bulkPull(any(Instant.class), any(Instant.class)))
            .thenThrow(new IOException("NVD network error"));

        assertThrows(IOException.class, () ->
            runner.run(new DefaultApplicationArguments("--nvd-sync", "--since=2026-04-01T00:00:00Z")));
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
}
