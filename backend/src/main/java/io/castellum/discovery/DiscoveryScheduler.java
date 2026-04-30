package io.castellum.discovery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Cron-driven passive discovery sweep. Mirrors {@link io.castellum.risk.RiskFeedScheduler}.
 *
 * <p>Default cron: {@code 0 0 *\/6 * * *} (every 6 hours). Tests pin the value to {@code "-"}
 * via {@code application-test.yml} so the scheduler does not fire during the test suite.
 *
 * <p>Failures are caught and logged at WARN — a single failed sweep must not propagate up
 * the scheduler thread and disable subsequent firings.
 */
@Component
public class DiscoveryScheduler {

    private static final Logger log = LoggerFactory.getLogger(DiscoveryScheduler.class);

    private final PassiveDiscoveryService service;

    public DiscoveryScheduler(PassiveDiscoveryService service) {
        this.service = service;
    }

    @Scheduled(cron = "${castellum.discovery.passive-sweep-cron:0 0 */6 * * *}", zone = "UTC")
    public void runScheduledSweep() {
        try {
            service.scheduledSweep();
        } catch (Exception e) {
            log.warn("Scheduled passive sweep failed: {}", e.getMessage());
        }
    }
}
