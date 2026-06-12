package io.castellum.discovery;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.scheduling.annotation.Scheduled;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Verifies the cron-driven {@link DevicePruneScheduler} (mirrors {@link DiscoverySchedulerTest}):
 * <ul>
 *   <li>delegates to {@link DevicePruneService#pruneStalePublicDevices()} when enabled;</li>
 *   <li>honors {@code castellum.discovery.public-device-prune.enabled=false} — no service call;</li>
 *   <li>swallows service exceptions so a single failed prune does not cancel future firings;</li>
 *   <li>pins the {@code @Scheduled} cron property name + default and the UTC zone.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class DevicePruneSchedulerTest {

    @Mock private DevicePruneService service;

    @Test
    void runScheduledPrune_enabled_delegatesToPruneService() {
        DevicePruneScheduler scheduler = new DevicePruneScheduler(service, true);

        scheduler.runScheduledPrune();

        verify(service, times(1)).pruneStalePublicDevices();
        verifyNoMoreInteractions(service);
    }

    @Test
    void runScheduledPrune_disabled_doesNotCallService() {
        DevicePruneScheduler scheduler = new DevicePruneScheduler(service, false);

        scheduler.runScheduledPrune();

        verifyNoInteractions(service);
    }

    @Test
    void runScheduledPrune_serviceThrows_swallowsException() {
        DevicePruneScheduler scheduler = new DevicePruneScheduler(service, true);
        doThrow(new RuntimeException("db down")).when(service).pruneStalePublicDevices();

        // No throw expected — a propagated exception would cancel all future @Scheduled runs.
        scheduler.runScheduledPrune();

        verify(service, times(1)).pruneStalePublicDevices();
    }

    @Test
    void runScheduledPrune_scheduledAnnotation_pinsCronPropertyAndUtcZone() throws Exception {
        Method tick = DevicePruneScheduler.class.getMethod("runScheduledPrune");
        Scheduled scheduled = tick.getAnnotation(Scheduled.class);

        assertThat(scheduled)
            .as("runScheduledPrune must be @Scheduled")
            .isNotNull();
        // Property name must match the test-suite pin (cron: "-") in src/test/resources/application.yml.
        assertThat(scheduled.cron())
            .isEqualTo("${castellum.discovery.public-device-prune.cron:0 30 3 * * *}");
        assertThat(scheduled.zone()).isEqualTo("UTC");
    }
}
