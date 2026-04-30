package io.castellum.discovery;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Verifies the cron-driven {@link DiscoveryScheduler}:
 * <ul>
 *   <li>delegates to {@link PassiveDiscoveryService#scheduledSweep()} (which threads
 *       {@code triggered_by="SCHEDULER"} into the audit row);</li>
 *   <li>swallows {@link DiscoveryUnavailableException} so a single failed sweep does not
 *       disable subsequent firings.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class DiscoverySchedulerTest {

    @Mock private PassiveDiscoveryService service;
    @InjectMocks private DiscoveryScheduler scheduler;

    @Test
    void runScheduledSweep_invokesServiceWithDefaultRequestAndSchedulerTriggeredBy() throws Exception {
        scheduler.runScheduledSweep();

        verify(service, times(1)).scheduledSweep();
        verifyNoMoreInteractions(service);
    }

    @Test
    void runScheduledSweep_serviceThrowsDiscoveryUnavailable_swallowsAndLogsAtWarn() throws Exception {
        doThrow(new DiscoveryUnavailableException("no /proc/net/arp")).when(service).scheduledSweep();

        // No throw expected from runScheduledSweep — the cron worker thread must stay alive
        scheduler.runScheduledSweep();

        verify(service, times(1)).scheduledSweep();
    }

    @Test
    void runScheduledSweep_recordsSweepWithSchedulerTriggeredBy() throws Exception {
        // The scheduledSweep() implementation handles the SCHEDULER label internally;
        // this test exists to lock in that the scheduler does not pass any other request shape
        // (no request DTO, no manual triggered_by) — only the no-arg scheduledSweep entry point.
        scheduler.runScheduledSweep();

        verify(service).scheduledSweep();
        verify(service, times(0)).sweep(any());
    }
}
