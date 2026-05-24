package io.castellum.scan;

import io.castellum.audit.AuditService;
import io.castellum.discovery.DeviceUpsertService;
import io.castellum.domain.Device;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Plain Mockito tests for {@link ScanExecutionService}. No Spring context.
 * Verifies status transitions, audit event emissions, and failure handling.
 */
@ExtendWith(MockitoExtension.class)
class ScanExecutionServiceTest {

    @Mock NmapRunner nmapRunner;
    @Mock ScanRepository scanRepository;
    @Mock NmapOutputParser nmapOutputParser;
    @Mock DeviceUpsertService deviceUpsertService;
    @Mock NetworkServiceRepository networkServiceRepository;
    @Mock AuditService auditService;

    ScanExecutionService service;

    @BeforeEach
    void setUp() {
        service = new ScanExecutionService(
            nmapRunner, scanRepository, nmapOutputParser,
            deviceUpsertService, networkServiceRepository, auditService);
    }

    // -----------------------------------------------------------------------
    // Helper: build a persisted scan stub
    // -----------------------------------------------------------------------

    private Scan stubScan(Long id, String cidr, String scanType) {
        Scan scan = new Scan();
        scan.setId(id);
        scan.setCidr(cidr);
        scan.setScanType(scanType);
        scan.setStatus(ScanStatus.PENDING);
        scan.setRequestedAt(Instant.now());
        return scan;
    }

    // -----------------------------------------------------------------------
    // (a) Success path: PENDING → RUNNING → COMPLETE + 2 audit events
    // -----------------------------------------------------------------------

    @Test
    void success_transitionsThroughRunningToComplete() throws Exception {
        Scan scan = stubScan(1L, "10.0.0.0/24", "PING_SWEEP");
        when(scanRepository.findById(1L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        NmapResult result = new NmapResult(0, "Nmap scan report for 10.0.0.1\nHost is up\n", "");
        when(nmapRunner.run(anyString(), any(ScanType.class))).thenReturn(result);

        NmapOutputParser.ParsedScan parsed = new NmapOutputParser.ParsedScan(List.of(), List.of());
        when(nmapOutputParser.parse(anyString(), any(ScanType.class))).thenReturn(parsed);

        service.executeAsync(1L);

        // Status must end as COMPLETE
        assertEquals(ScanStatus.COMPLETE, scan.getStatus(),
            "scan must transition to COMPLETE on success");
        assertNotNull(scan.getCompletedAt(), "completedAt must be set on COMPLETE");
        assertNull(scan.getFailureReason(), "failureReason must be null on success path");

        // Two audit events: SCAN_EXECUTE + SCAN_COMPLETE
        verify(auditService).recordEvent(eq("system"), eq("SCAN_EXECUTE"), eq("scan"), eq("1"), any());
        verify(auditService).recordEvent(eq("system"), eq("SCAN_COMPLETE"), eq("scan"), eq("1"), any());
        verify(auditService, never()).recordEvent(eq("system"), eq("SCAN_FAILED"), any(), any(), any());
    }

    // -----------------------------------------------------------------------
    // (b) IOException from runner → FAILED + failureReason + SCAN_FAILED audit
    // -----------------------------------------------------------------------

    @Test
    void runnerIOException_setsFailureReasonAndAuditsScanFailed() throws Exception {
        Scan scan = stubScan(2L, "10.0.0.0/24", "SERVICE_DETECT");
        when(scanRepository.findById(2L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));
        when(nmapRunner.run(anyString(), any(ScanType.class))).thenThrow(new IOException("connection refused"));

        service.executeAsync(2L);

        assertEquals(ScanStatus.FAILED, scan.getStatus(),
            "scan must transition to FAILED on IOException");
        assertNotNull(scan.getFailureReason(), "failureReason must be set");
        assertTrue(scan.getFailureReason().contains("IOException"),
            "failureReason must include the exception class name");
        assertTrue(scan.getFailureReason().contains("connection refused"),
            "failureReason must include the exception message");
        assertNotNull(scan.getCompletedAt(), "completedAt must be set on FAILED path");

        verify(auditService).recordEvent(eq("system"), eq("SCAN_FAILED"), eq("scan"), eq("2"), any());
        verify(auditService, never()).recordEvent(eq("system"), eq("SCAN_COMPLETE"), any(), any(), any());
    }

    // -----------------------------------------------------------------------
    // (c) RuntimeException from parser → FAILED + reason includes class name
    // -----------------------------------------------------------------------

    @Test
    void parserRuntimeException_setsFailureReasonWithClassName() throws Exception {
        Scan scan = stubScan(3L, "10.0.0.0/24", "PING_SWEEP");
        when(scanRepository.findById(3L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        NmapResult result = new NmapResult(0, "some output", "");
        when(nmapRunner.run(anyString(), any(ScanType.class))).thenReturn(result);
        when(nmapOutputParser.parse(anyString(), any(ScanType.class)))
            .thenThrow(new NullPointerException("unexpected null in parser"));

        service.executeAsync(3L);

        assertEquals(ScanStatus.FAILED, scan.getStatus());
        assertNotNull(scan.getFailureReason());
        assertTrue(scan.getFailureReason().startsWith("NullPointerException"),
            "failureReason must start with exception class name");
        verify(auditService).recordEvent(eq("system"), eq("SCAN_FAILED"), eq("scan"), eq("3"), any());
    }

    // -----------------------------------------------------------------------
    // (d) Missing scan row → SCAN_FAILED audit with "scan row gone"
    // -----------------------------------------------------------------------

    @Test
    void missingScanId_auditsScanFailedWithScanRowGone() {
        when(scanRepository.findById(99L)).thenReturn(Optional.empty());

        service.executeAsync(99L);

        // No save called (no entity to persist)
        verify(scanRepository, never()).save(any());
        // Audit must be emitted with the "scan row gone" payload
        ArgumentCaptor<Object> payloadCaptor = ArgumentCaptor.forClass(Object.class);
        verify(auditService).recordEvent(
            eq("system"), eq("SCAN_FAILED"), eq("scan"), eq("99"), payloadCaptor.capture());
        assertEquals("scan row gone", payloadCaptor.getValue());
    }

    // -----------------------------------------------------------------------
    // (e) Discovered host is upserted via DeviceUpsertService
    // -----------------------------------------------------------------------

    @Test
    void successWithHost_upsertsDeviceViaDeviceUpsertService() throws Exception {
        Scan scan = stubScan(4L, "10.0.1.0/24", "PING_SWEEP");
        when(scanRepository.findById(4L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        NmapResult result = new NmapResult(0, "stdout", "");
        when(nmapRunner.run(anyString(), any(ScanType.class))).thenReturn(result);

        NmapOutputParser.DiscoveredHost host =
            new NmapOutputParser.DiscoveredHost("10.0.1.5", "myhost");
        NmapOutputParser.ParsedScan parsed = new NmapOutputParser.ParsedScan(
            List.of(host), List.of());
        when(nmapOutputParser.parse(anyString(), any(ScanType.class))).thenReturn(parsed);

        Device device = new Device();
        device.setId(10L);
        when(deviceUpsertService.upsert(any())).thenReturn(device);

        service.executeAsync(4L);

        verify(deviceUpsertService).upsert(argThat(d ->
            "10.0.1.5".equals(d.ipAddress()) && "myhost".equals(d.hostname())));
        assertEquals(ScanStatus.COMPLETE, scan.getStatus());
    }
}
