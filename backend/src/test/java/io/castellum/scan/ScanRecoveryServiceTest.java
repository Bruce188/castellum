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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.doThrow;

@ExtendWith(MockitoExtension.class)
class ScanRecoveryServiceTest {

    private static final Instant PROCESS_START = Instant.parse("2026-05-26T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(PROCESS_START, ZoneOffset.UTC);

    @Mock ScanRepository scanRepository;
    @Mock ScanExecutionService scanExecutionService;
    @Mock AuditService auditService;

    private ScanRecoveryService service() {
        return new ScanRecoveryService(scanRepository, scanExecutionService, auditService, FIXED_CLOCK);
    }

    private static Scan scan(long id, ScanStatus status) {
        Scan s = new Scan();
        s.setId(id);
        s.setCidr("10.0.0.0/24");
        s.setScanType("PING_SWEEP");
        s.setStatus(status);
        s.setRequestedAt(PROCESS_START.minusSeconds(3600));
        return s;
    }

    // -----------------------------------------------------------------------
    // AC1 + AC2: staleness selection dispatches both pending and stale-running
    // -----------------------------------------------------------------------

    @Test
    void recover_selectsPendingAndStaleRunning_dispatchesBoth() {
        Scan pending = scan(1L, ScanStatus.PENDING);
        Scan staleRunning = scan(2L, ScanStatus.RUNNING);

        when(scanRepository.findRecoverable(PROCESS_START)).thenReturn(List.of(pending, staleRunning));
        when(scanRepository.claimForRecovery(1L, ScanStatus.PENDING)).thenReturn(1);
        when(scanRepository.claimForRecovery(2L, ScanStatus.RUNNING)).thenReturn(1);

        service().recoverInterruptedScans();

        verify(scanExecutionService).executeAsync(1L);
        verify(scanExecutionService).executeAsync(2L);
    }

    // -----------------------------------------------------------------------
    // AC4: CAS returns 0 => executeAsync NEVER called (idempotency proof)
    // -----------------------------------------------------------------------

    @Test
    void recover_casReturnsZero_skipsDispatch() {
        Scan running = scan(3L, ScanStatus.RUNNING);

        when(scanRepository.findRecoverable(PROCESS_START)).thenReturn(List.of(running));
        when(scanRepository.claimForRecovery(3L, ScanStatus.RUNNING)).thenReturn(0);

        service().recoverInterruptedScans();

        verify(scanExecutionService, never()).executeAsync(anyLong());
    }

    // -----------------------------------------------------------------------
    // AC3: single SCAN_RECOVERY audit with correct requeued count
    // -----------------------------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    void recover_emitsSingleScanRecoveryAudit_withRequeuedCount() {
        Scan pending = scan(4L, ScanStatus.PENDING);
        Scan staleRunning = scan(5L, ScanStatus.RUNNING);

        when(scanRepository.findRecoverable(PROCESS_START)).thenReturn(List.of(pending, staleRunning));
        when(scanRepository.claimForRecovery(4L, ScanStatus.PENDING)).thenReturn(1);
        when(scanRepository.claimForRecovery(5L, ScanStatus.RUNNING)).thenReturn(1);

        service().recoverInterruptedScans();

        ArgumentCaptor<Object> payloadCaptor = ArgumentCaptor.forClass(Object.class);
        verify(auditService, times(1)).recordEvent(
            eq("system"), eq("SCAN_RECOVERY"), eq("scan"), eq("-"), payloadCaptor.capture());

        Map<String, Object> payload = (Map<String, Object>) payloadCaptor.getValue();
        assertEquals(2, payload.get("requeued"), "requeued must be 2");
        assertEquals(1, payload.get("pending"), "pending tally must be 1");
        assertEquals(1, payload.get("staleRunning"), "staleRunning tally must be 1");
        assertEquals(PROCESS_START.toString(), payload.get("processStart"));
    }

    // -----------------------------------------------------------------------
    // AC3: empty recovery set still audits requeued=0
    // -----------------------------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    void recover_emptyRecoverySet_stillAuditsRequeuedZero() {
        when(scanRepository.findRecoverable(PROCESS_START)).thenReturn(List.of());

        service().recoverInterruptedScans();

        verify(scanExecutionService, never()).executeAsync(anyLong());

        ArgumentCaptor<Object> payloadCaptor = ArgumentCaptor.forClass(Object.class);
        verify(auditService, times(1)).recordEvent(
            eq("system"), eq("SCAN_RECOVERY"), eq("scan"), eq("-"), payloadCaptor.capture());

        Map<String, Object> payload = (Map<String, Object>) payloadCaptor.getValue();
        assertEquals(0, payload.get("requeued"));
    }

    // -----------------------------------------------------------------------
    // Mixed: only claimed rows dispatched
    // -----------------------------------------------------------------------

    @Test
    void recover_mixedClaim_onlyDispatchesClaimedRows() {
        Scan s1 = scan(6L, ScanStatus.PENDING);
        Scan s2 = scan(7L, ScanStatus.PENDING);

        when(scanRepository.findRecoverable(PROCESS_START)).thenReturn(List.of(s1, s2));
        when(scanRepository.claimForRecovery(6L, ScanStatus.PENDING)).thenReturn(1);
        when(scanRepository.claimForRecovery(7L, ScanStatus.PENDING)).thenReturn(0);

        service().recoverInterruptedScans();

        verify(scanExecutionService, times(1)).executeAsync(6L);
        verify(scanExecutionService, never()).executeAsync(7L);

        ArgumentCaptor<Object> payloadCaptor = ArgumentCaptor.forClass(Object.class);
        verify(auditService).recordEvent(
            anyString(), eq("SCAN_RECOVERY"), anyString(), anyString(), payloadCaptor.capture());

        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) payloadCaptor.getValue();
        assertEquals(1, payload.get("requeued"));
    }

    // -----------------------------------------------------------------------
    // Determinism: processStart derives from injected Clock (no Instant.now())
    // -----------------------------------------------------------------------

    @Test
    void construction_capturesProcessStartFromClock() {
        Instant customStart = Instant.parse("2026-01-15T08:00:00Z");
        Clock customClock = Clock.fixed(customStart, ZoneOffset.UTC);
        ScanRecoveryService svc = new ScanRecoveryService(
            scanRepository, scanExecutionService, auditService, customClock);

        // Prove the service uses the clock-derived processStart by checking
        // that findRecoverable is called with the expected instant when invoked
        when(scanRepository.findRecoverable(customStart)).thenReturn(List.of());

        svc.recoverInterruptedScans();

        verify(scanRepository).findRecoverable(customStart);
        verify(scanRepository, never()).findRecoverable(eq(PROCESS_START));
    }

    // -----------------------------------------------------------------------
    // Wide-CIDR routing: /20 (>1 chunk) dispatches executeWideAsync, not executeAsync
    // -----------------------------------------------------------------------

    @Test
    void recover_wideCidr_dispatchesExecuteWideAsync_notExecuteAsync() {
        Scan wide = new Scan();
        wide.setId(20L);
        wide.setCidr("10.0.0.0/20"); // 4 /22 chunks → isWideScan == true
        wide.setScanType("PING_SWEEP");
        wide.setStatus(ScanStatus.PENDING);
        wide.setRequestedAt(PROCESS_START.minusSeconds(3600));

        when(scanRepository.findRecoverable(PROCESS_START)).thenReturn(List.of(wide));
        when(scanRepository.claimForRecovery(20L, ScanStatus.PENDING)).thenReturn(1);

        service().recoverInterruptedScans();

        verify(scanExecutionService).executeWideAsync(20L);
        verify(scanExecutionService, never()).executeAsync(anyLong());
    }

    // -----------------------------------------------------------------------
    // Malformed-CIDR row does not abort sweep; valid subsequent rows still
    // dispatched and SCAN_RECOVERY audit still fires (pins Finding 1 guard)
    // -----------------------------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    void recover_malformedCidr_doesNotAbortSweep_auditStillFires() {
        Scan bad = new Scan();
        bad.setId(30L);
        bad.setCidr("garbage"); // will throw IllegalArgumentException via CidrValidator
        bad.setScanType("PING_SWEEP");
        bad.setStatus(ScanStatus.PENDING);
        bad.setRequestedAt(PROCESS_START.minusSeconds(3600));

        Scan good = scan(31L, ScanStatus.PENDING);

        when(scanRepository.findRecoverable(PROCESS_START)).thenReturn(List.of(bad, good));
        when(scanRepository.claimForRecovery(30L, ScanStatus.PENDING)).thenReturn(1);
        when(scanRepository.claimForRecovery(31L, ScanStatus.PENDING)).thenReturn(1);

        service().recoverInterruptedScans();

        // Bad row failed dispatch — must NOT count as requeued; good row dispatched
        verify(scanExecutionService, never()).executeAsync(30L);
        verify(scanExecutionService).executeAsync(31L);

        // SCAN_RECOVERY audit fires with requeued=1 (only the valid row)
        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(auditService, times(1)).recordEvent(
            eq("system"), eq("SCAN_RECOVERY"), eq("scan"), eq("-"), captor.capture());
        Map<String, Object> payload = (Map<String, Object>) captor.getValue();
        assertEquals(1, payload.get("requeued"), "bad-CIDR row must not count as requeued");
    }
}
