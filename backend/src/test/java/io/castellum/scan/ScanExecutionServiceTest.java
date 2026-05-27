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
    @Mock ScanRetryService scanRetryService;

    ScanExecutionService service;

    @BeforeEach
    void setUp() {
        service = new ScanExecutionService(
            nmapRunner, scanRepository, nmapOutputParser,
            deviceUpsertService, networkServiceRepository, auditService,
            scanRetryService);
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

    // -----------------------------------------------------------------------
    // (f) Phantom suppression: SERVICE_DETECT host with 0 open services is NOT persisted
    // -----------------------------------------------------------------------

    @Test
    void serviceDetect_hostWithNoOpenServices_isNotUpserted() throws Exception {
        Scan scan = stubScan(5L, "10.0.2.0/24", "SERVICE_DETECT");
        when(scanRepository.findById(5L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        NmapResult result = new NmapResult(0, "stdout", "");
        when(nmapRunner.run(anyString(), any(ScanType.class))).thenReturn(result);

        // Under -Pn this address is reported "up" but exposes no open ports — a phantom.
        NmapOutputParser.DiscoveredHost phantom =
            new NmapOutputParser.DiscoveredHost("10.0.2.0", null);
        NmapOutputParser.ParsedScan parsed = new NmapOutputParser.ParsedScan(
            List.of(phantom), List.of());
        when(nmapOutputParser.parse(anyString(), any(ScanType.class))).thenReturn(parsed);

        service.executeAsync(5L);

        // No device upsert, no service persistence for the phantom host.
        verify(deviceUpsertService, never()).upsert(any());
        verify(networkServiceRepository, never()).save(any());
        assertEquals(ScanStatus.COMPLETE, scan.getStatus(),
            "scan still completes successfully even when all hosts are phantoms");
    }

    // -----------------------------------------------------------------------
    // (g) SERVICE_DETECT host WITH >=1 open service IS persisted, with product + cpe
    // -----------------------------------------------------------------------

    @Test
    void serviceDetect_hostWithOpenService_isUpsertedWithProductAndCpe() throws Exception {
        Scan scan = stubScan(6L, "10.0.3.0/24", "SERVICE_DETECT");
        when(scanRepository.findById(6L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        NmapResult result = new NmapResult(0, "stdout", "");
        when(nmapRunner.run(anyString(), any(ScanType.class))).thenReturn(result);

        NmapOutputParser.DiscoveredHost realHost =
            new NmapOutputParser.DiscoveredHost("10.0.3.7", "real");
        NmapOutputParser.DiscoveredService svc = new NmapOutputParser.DiscoveredService(
            "10.0.3.7", 22, "tcp", "ssh", "9.6p1", "OpenSSH",
            "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*");
        NmapOutputParser.ParsedScan parsed = new NmapOutputParser.ParsedScan(
            List.of(realHost), List.of(svc));
        when(nmapOutputParser.parse(anyString(), any(ScanType.class))).thenReturn(parsed);

        Device device = new Device();
        device.setId(20L);
        when(deviceUpsertService.upsert(any())).thenReturn(device);
        when(networkServiceRepository.findByDeviceIdAndPortAndProtocol(20L, 22, "tcp"))
            .thenReturn(Optional.empty());

        service.executeAsync(6L);

        verify(deviceUpsertService).upsert(argThat(d -> "10.0.3.7".equals(d.ipAddress())));
        verify(networkServiceRepository).save(argThat(ns ->
            ns.getPort() == 22
                && "OpenSSH".equals(ns.getProduct())
                && "9.6p1".equals(ns.getVersion())
                && "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*".equals(ns.getCpe())));
        assertEquals(ScanStatus.COMPLETE, scan.getStatus());
    }
}
