package io.castellum.discovery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Cron-driven PUBLIC-device TTL prune. Mirrors {@link DiscoveryScheduler}.
 *
 * <p>Default cron: {@code 0 30 3 * * *} (daily 03:30 UTC). Tests pin the value to {@code "-"}
 * via {@code application.yml} in test resources so the scheduler does not fire during the
 * test suite. The {@code enabled} flag is the operator kill switch — when false the tick
 * returns without touching the service.
 *
 * <p>Failures are caught and logged — a single failed prune must not propagate up the
 * scheduler thread and disable subsequent firings.
 */
@Component
public class DevicePruneScheduler {

    private static final Logger log = LoggerFactory.getLogger(DevicePruneScheduler.class);

    private final DevicePruneService service;
    private final boolean enabled;

    public DevicePruneScheduler(DevicePruneService service,
                                @Value("${castellum.discovery.public-device-prune.enabled:true}") boolean enabled) {
        this.service = service;
        this.enabled = enabled;
    }

    @Scheduled(cron = "${castellum.discovery.public-device-prune.cron:0 30 3 * * *}", zone = "UTC")
    public void runScheduledPrune() {
        if (!enabled) {
            return;
        }
        try {
            service.pruneStalePublicDevices();
        } catch (Exception e) {
            // never propagate — the @Scheduled wrapper would cancel the task on uncaught
            log.error("Scheduled PUBLIC-device prune failed: {}", e.getMessage(), e);
        }
    }
}
