package io.castellum.scan;

import io.castellum.audit.AuditService;
import io.castellum.discovery.DeviceUpsertService;
import io.castellum.discovery.probe.DockerHostProbeService;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
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
 * Chunked wide-range scanning — execution loop (4b), observable through the
 * existing public surface (runner invocations, audit events, device upserts).
 *
 * <p>Every scan goes through the chunk loop: the CIDR is split into /22 chunks
 * (CidrChunker.chunkInto(cidr, 22)) and the existing single-scan flow runs once
 * per chunk, sequentially, in ascending network order. The whole-range CIDR is
 * never handed to nmap for ranges wider than /22.
 *
 * <p>Same mock harness as {@link ScanExecutionServiceTest} — no Spring context.
 */
@ExtendWith(MockitoExtension.class)
class ScanExecutionServiceChunkLoopTest {

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
    @Mock DockerHostProbeService dockerHostProbeService;

    ScanExecutionService service;

    @BeforeEach
    void setUp() {
        service = new ScanExecutionService(
            nmapRunner, scanRepository, nmapOutputParser,
            deviceUpsertService, networkServiceRepository, auditService,
            scanRetryService, riskCacheEvictor, deviceRepository, aliveHostResolver,
            dockerHostProbeService);
    }

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
    // (a) /20 PING_SWEEP → nmap runs once per /22 chunk, sequentially, in
    //     ascending network order; whole /20 never handed to the runner;
    //     SCAN_EXECUTE exactly once per SCAN (not per chunk); no extra
    //     per-chunk audit event types.
    // -----------------------------------------------------------------------

    @Test
    void pingSweep_slash20_runsFourSlash22ChunksSequentiallyInOrder() throws Exception {
        Scan scan = stubScan(200L, "10.0.0.0/20", "PING_SWEEP");
        when(scanRepository.findById(200L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        when(nmapRunner.run(anyString(), eq(ScanType.PING_SWEEP)))
            .thenReturn(new NmapResult(0, "stdout", ""));
        when(nmapOutputParser.parse(anyString(), any(ScanType.class)))
            .thenReturn(new NmapOutputParser.ParsedScan(List.of(), List.of()));

        service.executeAsync(200L);

        // One runner invocation per chunk, with the exact chunk CIDRs, in order.
        InOrder inOrder = inOrder(nmapRunner);
        inOrder.verify(nmapRunner).run("10.0.0.0/22", ScanType.PING_SWEEP);
        inOrder.verify(nmapRunner).run("10.0.4.0/22", ScanType.PING_SWEEP);
        inOrder.verify(nmapRunner).run("10.0.8.0/22", ScanType.PING_SWEEP);
        inOrder.verify(nmapRunner).run("10.0.12.0/22", ScanType.PING_SWEEP);
        verify(nmapRunner, times(4)).run(anyString(), any(ScanType.class));
        // The whole /20 must never reach nmap.
        verify(nmapRunner, never()).run(eq("10.0.0.0/20"), any(ScanType.class));

        assertEquals(ScanStatus.COMPLETE, scan.getStatus(),
            "a chunked scan must still terminate COMPLETE");

        // Audit cadence is per SCAN: exactly one SCAN_EXECUTE + one SCAN_COMPLETE,
        // and no additional (per-chunk) audit events of any type.
        verify(auditService, times(1)).recordEvent(
            eq("system"), eq("SCAN_EXECUTE"), eq("scan"), eq("200"), any());
        verify(auditService, times(1)).recordEvent(
            eq("system"), eq("SCAN_COMPLETE"), eq("scan"), eq("200"), any());
        verify(auditService, times(2)).recordEvent(
            anyString(), anyString(), anyString(), anyString(), any());
    }

    // -----------------------------------------------------------------------
    // (b) Fail-fast: chunk 2 of 4 throws → scan FAILED, failureReason names the
    //     failing chunk's CIDR, chunks 3 and 4 are never run.
    // -----------------------------------------------------------------------

    @Test
    void pingSweep_slash20_chunkTwoFails_failsFastAndNamesFailingChunk() throws Exception {
        Scan scan = stubScan(201L, "10.0.0.0/20", "PING_SWEEP");
        when(scanRepository.findById(201L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        // Chunk 1 succeeds; every other target (including, pre-feature, the whole /20)
        // throws — so chunk 2 is the first failure in the chunked flow.
        when(nmapRunner.run(anyString(), any(ScanType.class))).thenAnswer(inv -> {
            String target = inv.getArgument(0);
            if ("10.0.0.0/22".equals(target)) {
                return new NmapResult(0, "chunk1-stdout", "");
            }
            throw new IOException("nmap timed out");
        });
        lenient().when(nmapOutputParser.parse(eq("chunk1-stdout"), any(ScanType.class)))
            .thenReturn(new NmapOutputParser.ParsedScan(List.of(), List.of()));

        service.executeAsync(201L);

        assertEquals(ScanStatus.FAILED, scan.getStatus(),
            "a chunk failure must fail the whole scan");
        assertNotNull(scan.getFailureReason());
        assertTrue(scan.getFailureReason().contains("10.0.4.0/22"),
            "failureReason must name the failing chunk's CIDR: " + scan.getFailureReason());

        // Fail-fast: the remaining chunks must never be attempted.
        verify(nmapRunner, never()).run(eq("10.0.8.0/22"), any(ScanType.class));
        verify(nmapRunner, never()).run(eq("10.0.12.0/22"), any(ScanType.class));

        verify(auditService, times(1)).recordEvent(
            eq("system"), eq("SCAN_FAILED"), eq("scan"), eq("201"), any());
        verify(auditService, never()).recordEvent(
            eq("system"), eq("SCAN_COMPLETE"), any(), any(), any());
    }

    // -----------------------------------------------------------------------
    // (c) Device attribution unchanged: hosts discovered in DIFFERENT chunks
    //     all upsert with the SAME scanId.
    // -----------------------------------------------------------------------

    @Test
    void chunkedScan_hostsFromEveryChunk_upsertWithSameScanId() throws Exception {
        Scan scan = stubScan(202L, "10.0.0.0/21", "PING_SWEEP");
        when(scanRepository.findById(202L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        // Give each chunk distinct stdout so the parse stub can attribute hosts per chunk.
        when(nmapRunner.run(anyString(), any(ScanType.class))).thenAnswer(inv ->
            new NmapResult(0, "stdout-" + inv.getArgument(0), ""));
        when(nmapOutputParser.parse(anyString(), any(ScanType.class))).thenAnswer(inv -> {
            String stdout = inv.getArgument(0);
            if ("stdout-10.0.0.0/22".equals(stdout)) {
                return new NmapOutputParser.ParsedScan(
                    List.of(new NmapOutputParser.DiscoveredHost("10.0.0.7", "host-a", null)),
                    List.of());
            }
            if ("stdout-10.0.4.0/22".equals(stdout)) {
                return new NmapOutputParser.ParsedScan(
                    List.of(new NmapOutputParser.DiscoveredHost("10.0.4.9", "host-b", null)),
                    List.of());
            }
            return new NmapOutputParser.ParsedScan(List.of(), List.of());
        });

        Device device = new Device();
        device.setId(60L);
        lenient().when(deviceUpsertService.upsert(any(), any())).thenReturn(device);

        service.executeAsync(202L);

        // Both chunks' hosts upsert against the same scan id (202).
        verify(deviceUpsertService).upsert(argThat(d -> "10.0.0.7".equals(d.ipAddress())), eq(202L));
        verify(deviceUpsertService).upsert(argThat(d -> "10.0.4.9".equals(d.ipAddress())), eq(202L));
        verify(deviceUpsertService, times(2)).upsert(any(), eq(202L));
        assertEquals(ScanStatus.COMPLETE, scan.getStatus());
    }

    // -----------------------------------------------------------------------
    // (d) SERVICE_DETECT without skipHostDiscovery: the alive-host inventory is
    //     resolved exactly ONCE per scan against the FULL CIDR (each resolver
    //     call is a full device-inventory fetch), then filtered to each chunk
    //     in memory — observable through the per-chunk runner target lists.
    // -----------------------------------------------------------------------

    @Test
    void serviceDetect_slash21_resolvesAliveHostsOncePerScan_filtersPerChunk() throws Exception {
        Scan scan = stubScan(203L, "10.0.0.0/21", "SERVICE_DETECT");
        when(scanRepository.findById(203L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        // Whole-range inventory: one host in each /22 chunk.
        when(aliveHostResolver.aliveHostsIn("10.0.0.0/21"))
            .thenReturn(List.of("10.0.0.5", "10.0.4.5"));
        lenient().when(nmapRunner.run(anyList(), any(ScanType.class)))
            .thenReturn(new NmapResult(0, "stdout", ""));
        lenient().when(nmapOutputParser.parse(anyString(), any(ScanType.class)))
            .thenReturn(new NmapOutputParser.ParsedScan(List.of(), List.of()));

        service.executeAsync(203L);

        // Exactly one resolver call, against the full scan CIDR — never per chunk.
        verify(aliveHostResolver, times(1)).aliveHostsIn("10.0.0.0/21");
        verify(aliveHostResolver, times(1)).aliveHostsIn(anyString());
        verify(aliveHostResolver, never()).aliveHostsIn("10.0.0.0/22");
        verify(aliveHostResolver, never()).aliveHostsIn("10.0.4.0/22");

        // Each chunk's runner targets are the in-memory filtered subset of that
        // single whole-range alive list.
        verify(nmapRunner).run(eq(List.of("10.0.0.5")), eq(ScanType.SERVICE_DETECT));
        verify(nmapRunner).run(eq(List.of("10.0.4.5")), eq(ScanType.SERVICE_DETECT));
        verify(nmapRunner, never()).run(anyString(), any(ScanType.class));

        assertEquals(ScanStatus.COMPLETE, scan.getStatus());
    }

    // -----------------------------------------------------------------------
    // (e) Empty-inventory SERVICE_DETECT: the once-per-scan alive set is empty
    //     → the whole scan completes via the no-results path. The runner is
    //     NEVER invoked, and — unlike the normal completion tail — neither the
    //     docker host probe nor the self-check runs (legacy
    //     completeWithNoResults semantics: an empty inventory must not raise
    //     self-check findings).
    // -----------------------------------------------------------------------

    @Test
    void serviceDetect_emptyInventory_completesNoResults_withoutRunnerProbeOrSelfCheck() throws Exception {
        Scan scan = stubScan(204L, "10.0.0.0/21", "SERVICE_DETECT");
        when(scanRepository.findById(204L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));
        when(aliveHostResolver.aliveHostsIn("10.0.0.0/21")).thenReturn(List.of());

        service.executeAsync(204L);

        // No nmap on either overload; nothing parsed or persisted.
        verify(nmapRunner, never()).run(anyString(), any(ScanType.class));
        verify(nmapRunner, never()).run(anyList(), any(ScanType.class));
        verify(nmapOutputParser, never()).parse(anyString(), any(ScanType.class));
        verify(deviceUpsertService, never()).upsert(any(), any());

        // The probe/self-check tail must NOT run on the no-results path.
        verify(dockerHostProbeService, never()).probeHosts(any());
        verify(dockerHostProbeService, never()).runSelfCheck();

        // Clean success with the per-scan audit cadence intact.
        assertEquals(ScanStatus.COMPLETE, scan.getStatus());
        assertNotNull(scan.getCompletedAt());
        assertNull(scan.getFailureReason());
        verify(auditService, times(1)).recordEvent(
            eq("system"), eq("SCAN_EXECUTE"), eq("scan"), eq("204"), any());
        verify(auditService, times(1)).recordEvent(
            eq("system"), eq("SCAN_COMPLETE"), eq("scan"), eq("204"), any());
        verify(auditService, never()).recordEvent(
            eq("system"), eq("SCAN_FAILED"), any(), any(), any());
    }
}
