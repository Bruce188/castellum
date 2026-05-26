package io.castellum.scan;

import io.castellum.audit.AuditService;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScanRetryServiceTest {

    @Mock ScanRepository scanRepository;
    @Mock ScanExecutionService scanExecutionService;
    @Mock AuditService auditService;

    private Scan failed(long id, String reason, int retryCount, Instant completedAt) {
        Scan s = new Scan();
        s.setId(id);
        s.setCidr("10.0.0.0/24");
        s.setScanType("SERVICE_DETECT");
        s.setStatus(ScanStatus.FAILED);
        s.setFailureReason(reason);
        s.setRetryCount(retryCount);
        s.setCompletedAt(completedAt);
        s.setRequestedAt(completedAt == null ? Instant.now() : completedAt.minusSeconds(10));
        return s;
    }

    @Test
    void scheduleRetryIfApplicable_nmapTimeoutBelowCap_emitsSchedulingAudit() {
        Clock clock = Clock.fixed(Instant.parse("2026-05-26T00:00:00Z"), ZoneOffset.UTC);
        ScanRetryService svc = new ScanRetryService(scanRepository, scanExecutionService, auditService, clock);

        Scan s = failed(1L, "RuntimeException: nmap timed out after 5m", 0,
            Instant.parse("2026-05-26T00:00:00Z"));
        svc.scheduleRetryIfApplicable(s);

        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(auditService).recordEvent(eq("scheduler"), eq("SCAN_RETRY_SCHEDULED"), eq("scan"),
            eq("1"), captor.capture());
        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) captor.getValue();
        assertEquals(1, payload.get("nextAttempt"));
        assertEquals(60L, payload.get("backoffSeconds"));
    }

    @Test
    void scheduleRetryIfApplicable_atCap_doesNotEmit() {
        Clock clock = Clock.fixed(Instant.parse("2026-05-26T00:00:00Z"), ZoneOffset.UTC);
        ScanRetryService svc = new ScanRetryService(scanRepository, scanExecutionService, auditService, clock);

        Scan s = failed(2L, "RuntimeException: nmap timed out", ScanRetryService.MAX_RETRIES,
            Instant.parse("2026-05-26T00:00:00Z"));
        svc.scheduleRetryIfApplicable(s);

        verify(auditService, never()).recordEvent(anyString(), eq("SCAN_RETRY_SCHEDULED"), anyString(),
            anyString(), any());
    }

    @Test
    void scheduleRetryIfApplicable_nonTimeoutFailure_doesNotEmit() {
        Clock clock = Clock.fixed(Instant.parse("2026-05-26T00:00:00Z"), ZoneOffset.UTC);
        ScanRetryService svc = new ScanRetryService(scanRepository, scanExecutionService, auditService, clock);

        Scan s = failed(3L, "IOException: connection refused", 0,
            Instant.parse("2026-05-26T00:00:00Z"));
        svc.scheduleRetryIfApplicable(s);

        verify(auditService, never()).recordEvent(anyString(), eq("SCAN_RETRY_SCHEDULED"), anyString(),
            anyString(), any());
    }

    @Test
    void promoteDueRetries_eligibleScan_flipsToPending_incrementsCount_auditsSCAN_RETRY() {
        Instant failedAt = Instant.parse("2026-05-26T00:00:00Z");
        Instant now = failedAt.plusSeconds(61); // > 60s backoff for attempt 1
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        ScanRetryService svc = new ScanRetryService(scanRepository, scanExecutionService, auditService, clock);

        Scan s = failed(10L, "RuntimeException: nmap timed out", 0, failedAt);
        when(scanRepository.findByStatus(ScanStatus.FAILED)).thenReturn(List.of(s));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        svc.promoteDueRetries();

        assertEquals(ScanStatus.PENDING, s.getStatus(), "must flip back to PENDING");
        assertEquals(1, s.getRetryCount(), "retryCount must increment");
        verify(auditService).recordEvent(eq("scheduler"), eq("SCAN_RETRY"), eq("scan"),
            eq("10"), any());
        verify(scanExecutionService).executeAsync(10L);
    }

    @Test
    void promoteDueRetries_backoffNotElapsed_doesNotFlip() {
        Instant failedAt = Instant.parse("2026-05-26T00:00:00Z");
        Instant now = failedAt.plusSeconds(30); // < 60s backoff
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        ScanRetryService svc = new ScanRetryService(scanRepository, scanExecutionService, auditService, clock);

        Scan s = failed(11L, "RuntimeException: nmap timed out", 0, failedAt);
        when(scanRepository.findByStatus(ScanStatus.FAILED)).thenReturn(List.of(s));

        svc.promoteDueRetries();

        assertEquals(ScanStatus.FAILED, s.getStatus(), "stays FAILED until backoff elapses");
        verify(scanRepository, never()).save(any(Scan.class));
        verify(scanExecutionService, never()).executeAsync(any(Long.class));
    }

    @Test
    void promoteDueRetries_attempt2BackoffIs180s() {
        Instant failedAt = Instant.parse("2026-05-26T00:00:00Z");
        // 179s < 180s threshold — should NOT fire
        Clock tooEarly = Clock.fixed(failedAt.plusSeconds(179), ZoneOffset.UTC);
        ScanRetryService svc = new ScanRetryService(scanRepository, scanExecutionService, auditService, tooEarly);

        Scan s = failed(12L, "RuntimeException: nmap timed out", 1, failedAt);
        when(scanRepository.findByStatus(ScanStatus.FAILED)).thenReturn(List.of(s));

        svc.promoteDueRetries();
        assertEquals(ScanStatus.FAILED, s.getStatus(), "attempt-2 backoff is 180s; 179s elapsed must not fire");

        // 181s elapsed — should fire
        Clock now = Clock.fixed(failedAt.plusSeconds(181), ZoneOffset.UTC);
        svc = new ScanRetryService(scanRepository, scanExecutionService, auditService, now);
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));
        svc.promoteDueRetries();
        assertEquals(ScanStatus.PENDING, s.getStatus(), "attempt-2 backoff elapsed");
        assertEquals(2, s.getRetryCount());
    }

    @Test
    void promoteDueRetries_overCap_doesNotFlip() {
        Instant failedAt = Instant.parse("2026-05-26T00:00:00Z");
        Clock clock = Clock.fixed(failedAt.plusSeconds(10_000), ZoneOffset.UTC);
        ScanRetryService svc = new ScanRetryService(scanRepository, scanExecutionService, auditService, clock);

        Scan s = failed(13L, "RuntimeException: nmap timed out", ScanRetryService.MAX_RETRIES, failedAt);
        when(scanRepository.findByStatus(ScanStatus.FAILED)).thenReturn(List.of(s));

        svc.promoteDueRetries();

        assertEquals(ScanStatus.FAILED, s.getStatus(), "must stay FAILED after MAX_RETRIES attempts");
        verify(scanRepository, never()).save(any(Scan.class));
    }

    @Test
    void backoffSchedule_60s_180s() {
        assertEquals(60L, ScanRetryService.backoffSecondsForAttempt(1));
        assertEquals(180L, ScanRetryService.backoffSecondsForAttempt(2));
    }

    @Test
    void serviceConstruction_works() {
        Clock clock = Clock.fixed(Instant.parse("2026-05-26T00:00:00Z"), ZoneOffset.UTC);
        ScanRetryService svc = new ScanRetryService(scanRepository, scanExecutionService, auditService, clock);
        assertNotNull(svc);
    }
}
