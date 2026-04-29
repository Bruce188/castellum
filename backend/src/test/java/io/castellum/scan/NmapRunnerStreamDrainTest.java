package io.castellum.scan;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests that NmapRunner cleans up its drainer ExecutorService on all exit paths,
 * including InterruptedException (Task 5.5 — resource hygiene fix).
 */
class NmapRunnerStreamDrainTest {

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void run_shutsDownExecutorOnInterruption() throws Exception {
        AtomicBoolean shutdownNowCalled = new AtomicBoolean(false);
        AtomicReference<ExecutorService> createdExecutor = new AtomicReference<>();

        // Use the package-private factory constructor to spy on the executor
        NmapRunner runner = new NmapRunner(() -> {
            ExecutorService real = Executors.newFixedThreadPool(2);
            ExecutorService spy = new java.util.concurrent.ThreadPoolExecutor(
                2, 2, 0L, java.util.concurrent.TimeUnit.MILLISECONDS,
                new java.util.concurrent.LinkedBlockingQueue<>()) {
                @Override
                public java.util.List<Runnable> shutdownNow() {
                    shutdownNowCalled.set(true);
                    return super.shutdownNow();
                }
            };
            createdExecutor.set(spy);
            return spy;
        });

        Thread worker = new Thread(() -> {
            try {
                runner.run("192.168.1.0/24", ScanType.PING_SWEEP);
            } catch (Exception ignored) {
                // Expected to throw after interruption
            }
        });
        worker.setDaemon(true);
        worker.start();

        // Allow nmap to start and the drainer to be created
        Thread.sleep(200);
        worker.interrupt();
        worker.join(5000);

        // Verify that shutdownNow was called (i.e. the finally block executed)
        assertTrue(shutdownNowCalled.get(),
            "NmapRunner.run() must call drainer.shutdownNow() in the finally block");
    }
}
