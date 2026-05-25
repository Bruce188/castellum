package io.castellum.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * Async configuration for scan-execution background tasks.
 *
 * <p>Defines a named {@code scanTaskExecutor} bean so the pool is bounded and
 * distinct from any future async surface. Pool sizing is driven by
 * {@code castellum.scan.executor.*} configuration keys (with sensible defaults).
 *
 * <p>Rejection policy: {@link ThreadPoolExecutor.AbortPolicy} — callers see a
 * {@code TaskRejectedException} on queue saturation rather than silent drops.
 * {@code ScanController.submit} wraps the dispatch call in a try/catch so the
 * HTTP client never sees the exception; the PENDING row remains operator-visible.
 *
 * <p>Max in-flight: {@code max-pool-size + queue-capacity} scans before rejection.
 * At defaults (4 + 10) that is 14 concurrent/queued scans.
 */
@Configuration
@EnableAsync
@EnableScheduling
public class AsyncConfig {

    @Value("${castellum.scan.executor.core-pool-size:2}")
    private int corePoolSize;

    @Value("${castellum.scan.executor.max-pool-size:4}")
    private int maxPoolSize;

    @Value("${castellum.scan.executor.queue-capacity:10}")
    private int queueCapacity;

    @Value("${castellum.initial-sync.executor.core-pool-size:1}")
    private int initialSyncCorePoolSize;

    @Value("${castellum.initial-sync.executor.max-pool-size:1}")
    private int initialSyncMaxPoolSize;

    @Value("${castellum.initial-sync.executor.queue-capacity:0}")
    private int initialSyncQueueCapacity;

    @Bean("scanTaskExecutor")
    public ThreadPoolTaskExecutor scanTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(corePoolSize);
        executor.setMaxPoolSize(maxPoolSize);
        executor.setQueueCapacity(queueCapacity);
        executor.setThreadNamePrefix("scan-exec-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.AbortPolicy());
        executor.initialize();
        return executor;
    }

    /**
     * Dedicated single-threaded executor for the initial data-sync background job.
     *
     * <p>Pool is intentionally minimal (corePoolSize=1, maxPoolSize=1, queueCapacity=0)
     * so at most one sync runs at a time. The {@code AtomicBoolean inFlight} guard in
     * {@code InitialSyncService} short-circuits before submit, so the {@code AbortPolicy}
     * here is a belt-and-braces defence only.
     *
     * <p>Isolation from {@code scanTaskExecutor} prevents a multi-hour NVD bulk pull from
     * starving scan-dispatch slots.
     */
    @Bean("initialSyncTaskExecutor")
    public ThreadPoolTaskExecutor initialSyncTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(initialSyncCorePoolSize);
        executor.setMaxPoolSize(initialSyncMaxPoolSize);
        executor.setQueueCapacity(initialSyncQueueCapacity);
        executor.setThreadNamePrefix("initial-sync-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.AbortPolicy());
        executor.initialize();
        return executor;
    }
}
