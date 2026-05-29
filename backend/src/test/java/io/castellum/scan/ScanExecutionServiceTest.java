package io.castellum.scan;

import io.castellum.audit.AuditService;
import io.castellum.discovery.DeviceUpsertService;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
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
    @Mock io.castellum.risk.RiskCacheEvictor riskCacheEvictor;
    @Mock DeviceRepository deviceRepository;
    @Mock AliveHostResolver aliveHostResolver;

    ScanExecutionService service;

    @BeforeEach
    void setUp() {
        service = new ScanExecutionService(
            nmapRunner, scanRepository, nmapOutputParser,
            deviceUpsertService, networkServiceRepository, auditService,
            scanRetryService, riskCacheEvictor, deviceRepository, aliveHostResolver);
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
        // SERVICE_DETECT now resolves alive hosts and runs the explicit-host-list overload.
        when(aliveHostResolver.aliveHostsIn("10.0.0.0/24")).thenReturn(List.of("10.0.0.5"));
        when(nmapRunner.run(anyList(), any(ScanType.class))).thenThrow(new IOException("connection refused"));

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
            new NmapOutputParser.DiscoveredHost("10.0.1.5", "myhost", null);
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
    // (f) Alive-host path: a known-up SERVICE_DETECT host with 0 open services IS upserted.
    //     Phantom suppression only applied on the -Pn whole-CIDR fallback; the alive-host
    //     path targets only hosts a prior PING_SWEEP confirmed up, so a host with no open
    //     ports is a real device that must NOT be dropped.
    // -----------------------------------------------------------------------

    @Test
    void serviceDetect_aliveHostWithNoOpenServices_isStillUpserted() throws Exception {
        Scan scan = stubScan(5L, "10.0.2.0/24", "SERVICE_DETECT");
        when(scanRepository.findById(5L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        // PING_SWEEP confirmed this host up; it simply exposes no open ports right now.
        when(aliveHostResolver.aliveHostsIn("10.0.2.0/24")).thenReturn(List.of("10.0.2.7"));

        NmapResult result = new NmapResult(0, "stdout", "");
        when(nmapRunner.run(anyList(), any(ScanType.class))).thenReturn(result);

        NmapOutputParser.DiscoveredHost aliveNoPorts =
            new NmapOutputParser.DiscoveredHost("10.0.2.7", null, null);
        NmapOutputParser.ParsedScan parsed = new NmapOutputParser.ParsedScan(
            List.of(aliveNoPorts), List.of());
        when(nmapOutputParser.parse(anyString(), any(ScanType.class))).thenReturn(parsed);

        Device device = new Device();
        device.setId(50L);
        when(deviceUpsertService.upsert(any())).thenReturn(device);

        service.executeAsync(5L);

        // The known-up host IS upserted (no phantom suppression on the alive-host path).
        verify(deviceUpsertService).upsert(argThat(d -> "10.0.2.7".equals(d.ipAddress())));
        // No services to persist.
        verify(networkServiceRepository, never()).save(any());
        assertEquals(ScanStatus.COMPLETE, scan.getStatus());
    }

    // -----------------------------------------------------------------------
    // (f2) SERVICE_DETECT empty alive set → short-circuit COMPLETE, runner never called.
    // -----------------------------------------------------------------------

    @Test
    void serviceDetect_emptyAliveSet_shortCircuitsToCompleteWithoutRunningNmap() throws Exception {
        Scan scan = stubScan(50L, "10.0.9.0/24", "SERVICE_DETECT");
        when(scanRepository.findById(50L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));
        when(aliveHostResolver.aliveHostsIn("10.0.9.0/24")).thenReturn(List.of());

        service.executeAsync(50L);

        // nmap must NOT run on either overload — no whole-range fallback.
        verify(nmapRunner, never()).run(anyString(), any(ScanType.class));
        verify(nmapRunner, never()).run(anyList(), any(ScanType.class));
        // Parser never invoked; no devices/services persisted.
        verify(nmapOutputParser, never()).parse(anyString(), any(ScanType.class));
        verify(deviceUpsertService, never()).upsert(any());
        verify(networkServiceRepository, never()).save(any());
        // Still a clean success.
        assertEquals(ScanStatus.COMPLETE, scan.getStatus());
        assertNotNull(scan.getCompletedAt());
        assertNull(scan.getFailureReason());
        verify(auditService).recordEvent(eq("system"), eq("SCAN_COMPLETE"), eq("scan"), eq("50"), any());
        verify(auditService, never()).recordEvent(eq("system"), eq("SCAN_FAILED"), any(), any(), any());
    }

    // -----------------------------------------------------------------------
    // (g) SERVICE_DETECT host WITH >=1 open service IS persisted, with product + cpe
    // -----------------------------------------------------------------------

    @Test
    void serviceDetect_hostWithOpenService_isUpsertedWithProductAndCpe() throws Exception {
        Scan scan = stubScan(6L, "10.0.3.0/24", "SERVICE_DETECT");
        when(scanRepository.findById(6L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));
        when(aliveHostResolver.aliveHostsIn("10.0.3.0/24")).thenReturn(List.of("10.0.3.7"));

        NmapResult result = new NmapResult(0, "stdout", "");
        when(nmapRunner.run(anyList(), any(ScanType.class))).thenReturn(result);

        NmapOutputParser.DiscoveredHost realHost =
            new NmapOutputParser.DiscoveredHost("10.0.3.7", "real", null);
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

    // -----------------------------------------------------------------------
    // (h) OS_FINGERPRINT matched host → OS fields persisted on Device
    // -----------------------------------------------------------------------

    @Test
    void osFingerprint_matchedHost_persistsOsFieldsOnDevice() throws Exception {
        Scan scan = stubScan(7L, "10.0.4.0/24", "OS_FINGERPRINT");
        when(scanRepository.findById(7L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        NmapResult result = new NmapResult(0, "stdout", "");
        when(nmapRunner.run(anyString(), any(ScanType.class))).thenReturn(result);

        NmapOutputParser.OsMatch osMatch =
            new NmapOutputParser.OsMatch("Linux 5.4 - 5.15", 96, "cpe:/o:linux:linux_kernel:5");
        NmapOutputParser.DiscoveredHost host =
            new NmapOutputParser.DiscoveredHost("10.0.4.9", "router", osMatch);
        NmapOutputParser.ParsedScan parsed = new NmapOutputParser.ParsedScan(
            List.of(host), List.of());
        when(nmapOutputParser.parse(anyString(), any(ScanType.class))).thenReturn(parsed);

        Device device = new Device();
        device.setId(30L);
        when(deviceUpsertService.upsert(any())).thenReturn(device);

        service.executeAsync(7L);

        verify(deviceRepository).save(argThat(d ->
            "Linux 5.4 - 5.15".equals(d.getOsName())
                && d.getOsAccuracy() != null
                && d.getOsAccuracy() == 96
                && "cpe:/o:linux:linux_kernel:5".equals(d.getOsCpe())));
        assertEquals(ScanStatus.COMPLETE, scan.getStatus());
    }

    // -----------------------------------------------------------------------
    // (i) OS_FINGERPRINT host with no OS match → Device NOT re-saved
    // -----------------------------------------------------------------------

    @Test
    void osFingerprint_noMatch_doesNotResaveDevice() throws Exception {
        Scan scan = stubScan(8L, "10.0.5.0/24", "OS_FINGERPRINT");
        when(scanRepository.findById(8L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        NmapResult result = new NmapResult(0, "stdout", "");
        when(nmapRunner.run(anyString(), any(ScanType.class))).thenReturn(result);

        NmapOutputParser.DiscoveredHost host =
            new NmapOutputParser.DiscoveredHost("10.0.5.3", "nooshost", null);
        NmapOutputParser.ParsedScan parsed = new NmapOutputParser.ParsedScan(
            List.of(host), List.of());
        when(nmapOutputParser.parse(anyString(), any(ScanType.class))).thenReturn(parsed);

        Device device = new Device();
        device.setId(31L);
        when(deviceUpsertService.upsert(any())).thenReturn(device);

        service.executeAsync(8L);

        verify(deviceRepository, never()).save(any());
    }

    // -----------------------------------------------------------------------
    // (j) SERVICE_DETECT with non-null OsMatch → OS NOT persisted (wrong scan type)
    // -----------------------------------------------------------------------

    @Test
    void serviceDetect_doesNotPersistOs() throws Exception {
        Scan scan = stubScan(9L, "10.0.6.0/24", "SERVICE_DETECT");
        when(scanRepository.findById(9L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));
        when(aliveHostResolver.aliveHostsIn("10.0.6.0/24")).thenReturn(List.of("10.0.6.2"));

        NmapResult result = new NmapResult(0, "stdout", "");
        when(nmapRunner.run(anyList(), any(ScanType.class))).thenReturn(result);

        NmapOutputParser.OsMatch osMatch =
            new NmapOutputParser.OsMatch("Windows 10", 85, "cpe:/o:microsoft:windows_10");
        NmapOutputParser.DiscoveredHost host =
            new NmapOutputParser.DiscoveredHost("10.0.6.2", "winbox", osMatch);
        // One open service so phantom suppression does not skip this host
        NmapOutputParser.DiscoveredService svc = new NmapOutputParser.DiscoveredService(
            "10.0.6.2", 445, "tcp", "microsoft-ds", null, "Samba",
            "cpe:2.3:a:microsoft:smb:*:*:*:*:*:*:*:*");
        NmapOutputParser.ParsedScan parsed = new NmapOutputParser.ParsedScan(
            List.of(host), List.of(svc));
        when(nmapOutputParser.parse(anyString(), any(ScanType.class))).thenReturn(parsed);

        Device device = new Device();
        device.setId(32L);
        when(deviceUpsertService.upsert(any())).thenReturn(device);
        when(networkServiceRepository.findByDeviceIdAndPortAndProtocol(32L, 445, "tcp"))
            .thenReturn(Optional.empty());

        service.executeAsync(9L);

        verify(deviceRepository, never()).save(any());
    }
}
