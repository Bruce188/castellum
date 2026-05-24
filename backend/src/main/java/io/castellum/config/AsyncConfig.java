package io.castellum.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
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
public class AsyncConfig {

    @Value("${castellum.scan.executor.core-pool-size:2}")
    private int corePoolSize;

    @Value("${castellum.scan.executor.max-pool-size:4}")
    private int maxPoolSize;

    @Value("${castellum.scan.executor.queue-capacity:10}")
    private int queueCapacity;

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
}
