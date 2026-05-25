package io.castellum.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Lightweight @SpringBootTest that verifies the {@code scanTaskExecutor} and
 * {@code initialSyncTaskExecutor} beans are wired with the configured pool properties.
 */
@SpringBootTest
@TestPropertySource(properties = {
    "castellum.scan.executor.core-pool-size=3",
    "castellum.scan.executor.max-pool-size=6",
    "castellum.scan.executor.queue-capacity=20"
})
class AsyncConfigTest {

    @Autowired
    private ThreadPoolTaskExecutor scanTaskExecutor;

    @Autowired
    @Qualifier("initialSyncTaskExecutor")
    private ThreadPoolTaskExecutor initialSyncTaskExecutor;

    @Test
    void scanTaskExecutor_isBoundedThreadPool_withConfiguredProperties() {
        assertNotNull(scanTaskExecutor, "scanTaskExecutor bean must be present");
        assertEquals(3, scanTaskExecutor.getCorePoolSize(),
            "core-pool-size must reflect property override");
        assertEquals(6, scanTaskExecutor.getMaxPoolSize(),
            "max-pool-size must reflect property override");
        assertEquals(20, scanTaskExecutor.getQueueCapacity(),
            "queue-capacity must reflect property override");
        assertTrue(scanTaskExecutor.getThreadNamePrefix().startsWith("scan-exec-"),
            "thread-name-prefix must be scan-exec-");
    }

    @Test
    void initialSyncTaskExecutor_isSingleThreaded_withDefaultProperties() {
        assertNotNull(initialSyncTaskExecutor, "initialSyncTaskExecutor bean must be present");
        assertEquals(1, initialSyncTaskExecutor.getCorePoolSize(),
            "initial-sync executor core-pool-size must be 1");
        assertEquals(1, initialSyncTaskExecutor.getMaxPoolSize(),
            "initial-sync executor max-pool-size must be 1");
        assertEquals(0, initialSyncTaskExecutor.getQueueCapacity(),
            "initial-sync executor queue-capacity must be 0");
        assertTrue(initialSyncTaskExecutor.getThreadNamePrefix().startsWith("initial-sync-"),
            "thread-name-prefix must be initial-sync-");
    }
}
