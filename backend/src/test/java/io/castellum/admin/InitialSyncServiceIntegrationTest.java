package io.castellum.admin;

import io.castellum.cve.NvdSyncService;
import io.castellum.risk.EpssIngestionService;
import io.castellum.risk.KevIngestionService;
import io.castellum.web.dto.InitialSyncRequest;
import io.castellum.web.dto.InitialSyncResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Integration test for {@link InitialSyncService} using the real {@code initialSyncTaskExecutor}
 * bean. Verifies that concurrent re-sync attempts are properly gated by the {@code AtomicBoolean
 * inFlight} guard.
 */
@SpringBootTest
class InitialSyncServiceIntegrationTest {

    @Autowired
    InitialSyncService initialSyncService;

    @MockBean
    NvdSyncService nvdSyncService;

    @MockBean
    EpssIngestionService epssIngestionService;

    @MockBean
    KevIngestionService kevIngestionService;

    @Test
    void firstCall_returnsStarted() throws Exception {
        CountDownLatch hold = new CountDownLatch(1);
        CountDownLatch running = new CountDownLatch(1);

        doAnswer(inv -> {
            running.countDown();
            hold.await(5, TimeUnit.SECONDS);
            return null;
        }).when(nvdSyncService).bulkPull(any(), any());

        try {
            InitialSyncResponse resp = initialSyncService.trigger(InitialSyncRequest.defaults(), "admin");
            assertTrue(running.await(5, TimeUnit.SECONDS), "NVD mock must have started");

            assertEquals("started", resp.status());
            assertNotNull(resp.startedAt());
        } finally {
            hold.countDown();
            // allow background task to drain
            Thread.sleep(200);
        }
    }

    @Test
    void secondCallWhileInFlight_returnsAlreadyRunning_andDownstreamInvokedOnce() throws Exception {
        CountDownLatch hold = new CountDownLatch(1);
        CountDownLatch running = new CountDownLatch(1);

        doAnswer(inv -> {
            running.countDown();
            hold.await(5, TimeUnit.SECONDS);
            return null;
        }).when(nvdSyncService).bulkPull(any(), any());

        try {
            InitialSyncResponse first = initialSyncService.trigger(InitialSyncRequest.defaults(), "test");
            assertTrue(running.await(5, TimeUnit.SECONDS), "First sync must start running");

            InitialSyncResponse second = initialSyncService.trigger(InitialSyncRequest.defaults(), "test");

            assertEquals("started", first.status());
            assertEquals("already-running", second.status());
            assertEquals(first.startedAt(), second.startedAt(), "startedAt must be the same");
        } finally {
            hold.countDown();
            Thread.sleep(500); // let task complete + finally clear
        }

        // downstream services invoked exactly once (not twice)
        verify(nvdSyncService, times(1)).bulkPull(any(), any());
    }

    @Test
    void twoParallelPosts_secondReturnsAlreadyRunning_getReportsRunningTrueDuringAndFalseAfter() throws Exception {
        CountDownLatch hold = new CountDownLatch(1);
        CountDownLatch running = new CountDownLatch(1);

        doAnswer(inv -> {
            running.countDown();
            hold.await(5, TimeUnit.SECONDS);
            return null;
        }).when(nvdSyncService).bulkPull(any(), any());

        try {
            // First POST — starts the job
            InitialSyncResponse first = initialSyncService.trigger(InitialSyncRequest.defaults(), "admin");
            assertTrue(running.await(5, TimeUnit.SECONDS), "Background job must have started");

            // Second POST — should be gated out
            InitialSyncResponse second = initialSyncService.trigger(InitialSyncRequest.defaults(), "admin");
            assertEquals("started", first.status());
            assertEquals("already-running", second.status());

            // GET-during: isInFlight must be true while the latch is held
            assertTrue(initialSyncService.isInFlight(), "isInFlight() must return true while job is executing");
            assertNotNull(initialSyncService.getStartedAt(), "getStartedAt() must not be null while in-flight");
        } finally {
            // Release latch so the background thread can finish
            hold.countDown();
        }

        // Wait for the background task to finish and clear inFlight
        long deadline = System.currentTimeMillis() + 5_000;
        while (initialSyncService.isInFlight() && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }

        // GET-after: isInFlight must now be false
        assertFalse(initialSyncService.isInFlight(), "isInFlight() must return false after job completes");
    }
}
