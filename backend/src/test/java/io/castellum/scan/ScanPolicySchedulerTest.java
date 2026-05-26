package io.castellum.scan;

import io.castellum.audit.AuditService;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScanPolicySchedulerTest {

    @Mock ScanPolicyRepository policyRepository;
    @Mock ScanRepository scanRepository;
    @Mock ScanExecutionService scanExecutionService;
    @Mock AuditService auditService;

    private ScanPolicy enabledPolicy(long id, String cron, Instant created, Instant lastTriggered) {
        ScanPolicy p = new ScanPolicy("test-" + id, cron, "10.0.0.0/24", "PING_SWEEP", true);
        p.setId(id);
        p.setCreatedAt(created);
        p.setLastTriggeredAt(lastTriggered);
        return p;
    }

    @Test
    void policyFiresWhenCronNextElapsed_submitsScan_updatesLastTriggered_audits() {
        // Cron "0 * * * * *" = fires at second 0 of every minute. lastTriggered=01:00:00 →
        // next-fire = 01:01:00. Set now=01:02:30 so the next-fire has clearly elapsed.
        Instant base = Instant.parse("2026-05-26T01:02:30Z");
        Clock clock = Clock.fixed(base, ZoneOffset.UTC);
        ScanPolicy p = enabledPolicy(11L, "0 * * * * *",
            Instant.parse("2026-05-26T01:00:00Z"),
            Instant.parse("2026-05-26T01:00:00Z"));
        when(policyRepository.findByEnabledTrue()).thenReturn(List.of(p));

        Scan saved = new Scan();
        saved.setId(77L);
        when(scanRepository.save(any(Scan.class))).thenReturn(saved);

        ScanPolicyScheduler sched = new ScanPolicyScheduler(policyRepository, scanRepository,
            scanExecutionService, auditService, clock);
        sched.checkPolicies();

        // (a) Scan row created with the policy's CIDR/type
        verify(scanRepository).save(argThat(s -> "10.0.0.0/24".equals(s.getCidr())
            && "PING_SWEEP".equals(s.getScanType())));
        // (b) lastTriggeredAt was bumped
        verify(policyRepository).save(argThat(pp -> pp.getLastTriggeredAt() != null));
        // (c) Audit emitted
        verify(auditService).recordEvent(eq("scheduler"), eq("SCAN_POLICY_TRIGGER"),
            eq("scan_policy"), eq("11"), any());
        // (d) Async execution dispatched
        verify(scanExecutionService).executeAsync(anyLong());
    }

    @Test
    void policyDoesNotFireBeforeCronNext() {
        // Cron "0 0 * * * *" = top of every hour. lastTriggered=01:00:00 → next=02:00:00.
        // now=01:30:00 is well before next — must NOT fire.
        Instant base = Instant.parse("2026-05-26T01:30:00Z");
        Clock clock = Clock.fixed(base, ZoneOffset.UTC);
        ScanPolicy p = enabledPolicy(12L, "0 0 * * * *",
            Instant.parse("2026-05-26T01:00:00Z"),
            Instant.parse("2026-05-26T01:00:00Z"));
        when(policyRepository.findByEnabledTrue()).thenReturn(List.of(p));

        ScanPolicyScheduler sched = new ScanPolicyScheduler(policyRepository, scanRepository,
            scanExecutionService, auditService, clock);
        sched.checkPolicies();

        verify(scanRepository, never()).save(any(Scan.class));
        verify(auditService, never()).recordEvent(any(), eq("SCAN_POLICY_TRIGGER"), any(), any(), any());
    }

    @Test
    void disabledPoliciesNeverConsidered() {
        Instant base = Instant.parse("2026-05-26T01:00:30Z");
        Clock clock = Clock.fixed(base, ZoneOffset.UTC);
        when(policyRepository.findByEnabledTrue()).thenReturn(List.of());

        ScanPolicyScheduler sched = new ScanPolicyScheduler(policyRepository, scanRepository,
            scanExecutionService, auditService, clock);
        sched.checkPolicies();

        verify(scanRepository, never()).save(any(Scan.class));
    }
}
