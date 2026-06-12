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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Chunked wide-range scanning — chunk-progress persistence and the
 * skipHostDiscovery flag (4b).
 *
 * <p>At the RUNNING transition the service sets {@code chunksTotal} to the chunk
 * count and {@code chunksDone} to 0 (or to the persisted resume index for a
 * retried/recovered wide scan), then persists {@code chunksDone}
 * incrementally as each chunk finishes. {@code skipHostDiscovery=true} makes
 * SERVICE_DETECT scan the whole chunk CIDR (-Pn argv path) without consulting
 * the alive-host resolver; PING_SWEEP and OS_FINGERPRINT ignore the flag.
 *
 * <p>Same mock harness as {@link ScanExecutionServiceTest} — no Spring context.
 */
@ExtendWith(MockitoExtension.class)
class ScanExecutionServiceChunkProgressTest {

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
    // (a) RUNNING transition seeds chunksTotal = chunk count, chunksDone = 0,
    //     and that state is SAVED before any chunk runs.
    // -----------------------------------------------------------------------

    @Test
    void runningTransition_savesChunksTotalFourAndChunksDoneZero() throws Exception {
        Scan scan = stubScan(300L, "10.0.0.0/20", "PING_SWEEP");
        when(scanRepository.findById(300L)).thenReturn(Optional.of(scan));

        List<String> snapshots = new ArrayList<>();
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> {
            Scan s = inv.getArgument(0);
            snapshots.add(s.getStatus() + ":" + s.getChunksTotal() + ":" + s.getChunksDone());
            return s;
        });

        when(nmapRunner.run(anyString(), any(ScanType.class)))
            .thenReturn(new NmapResult(0, "stdout", ""));
        when(nmapOutputParser.parse(anyString(), any(ScanType.class)))
            .thenReturn(new NmapOutputParser.ParsedScan(List.of(), List.of()));

        service.executeAsync(300L);

        assertFalse(snapshots.isEmpty(), "the RUNNING transition must be persisted");
        assertEquals("RUNNING:4:0", snapshots.get(0),
            "first save must carry RUNNING with chunksTotal=4, chunksDone=0; saves were " + snapshots);
    }

    // -----------------------------------------------------------------------
    // (b) /20 PING_SWEEP — chunksDone persisted incrementally 1,2,3,4;
    //     final state COMPLETE with chunksDone=4.
    // -----------------------------------------------------------------------

    @Test
    void slash20_chunksDonePersistedIncrementally_finalCompleteAtFour() throws Exception {
        Scan scan = stubScan(301L, "10.0.0.0/20", "PING_SWEEP");
        when(scanRepository.findById(301L)).thenReturn(Optional.of(scan));

        List<Integer> chunksDoneAtSave = new ArrayList<>();
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> {
            Scan s = inv.getArgument(0);
            chunksDoneAtSave.add(s.getChunksDone());
            return s;
        });

        when(nmapRunner.run(anyString(), any(ScanType.class)))
            .thenReturn(new NmapResult(0, "stdout", ""));
        when(nmapOutputParser.parse(anyString(), any(ScanType.class)))
            .thenReturn(new NmapOutputParser.ParsedScan(List.of(), List.of()));

        service.executeAsync(301L);

        assertThat(chunksDoneAtSave)
            .as("chunksDone must be persisted incrementally per finished chunk")
            .containsSubsequence(0, 1, 2, 3, 4);

        assertEquals(ScanStatus.COMPLETE, scan.getStatus());
        assertEquals(4, scan.getChunksTotal());
        assertEquals(4, scan.getChunksDone());
    }

    // -----------------------------------------------------------------------
    // (c) /22-or-smaller is one chunk: chunksTotal=1, chunksDone=1 on COMPLETE,
    //     behavior otherwise identical to today.
    // -----------------------------------------------------------------------

    @Test
    void slash24_singleChunk_chunksTotalOneDoneOneOnComplete() throws Exception {
        Scan scan = stubScan(302L, "192.168.1.0/24", "PING_SWEEP");
        when(scanRepository.findById(302L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        when(nmapRunner.run(anyString(), any(ScanType.class)))
            .thenReturn(new NmapResult(0, "stdout", ""));
        when(nmapOutputParser.parse(anyString(), any(ScanType.class)))
            .thenReturn(new NmapOutputParser.ParsedScan(List.of(), List.of()));

        service.executeAsync(302L);

        // Exactly one runner invocation, against the unchanged CIDR.
        verify(nmapRunner, times(1)).run(anyString(), any(ScanType.class));
        verify(nmapRunner).run("192.168.1.0/24", ScanType.PING_SWEEP);

        assertEquals(ScanStatus.COMPLETE, scan.getStatus());
        assertEquals(1, scan.getChunksTotal());
        assertEquals(1, scan.getChunksDone());
    }

    // -----------------------------------------------------------------------
    // (d) Fail-fast: chunk 2 of 4 throws → FAILED with chunksDone stuck at 1.
    // -----------------------------------------------------------------------

    @Test
    void chunkTwoFails_chunksDoneStaysAtOne() throws Exception {
        Scan scan = stubScan(303L, "10.0.0.0/20", "PING_SWEEP");
        when(scanRepository.findById(303L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        when(nmapRunner.run(anyString(), any(ScanType.class))).thenAnswer(inv -> {
            String target = inv.getArgument(0);
            if ("10.0.0.0/22".equals(target)) {
                return new NmapResult(0, "chunk1-stdout", "");
            }
            throw new IOException("nmap timed out");
        });
        lenient().when(nmapOutputParser.parse(eq("chunk1-stdout"), any(ScanType.class)))
            .thenReturn(new NmapOutputParser.ParsedScan(List.of(), List.of()));

        service.executeAsync(303L);

        assertEquals(ScanStatus.FAILED, scan.getStatus());
        assertEquals(4, scan.getChunksTotal());
        assertEquals(1, scan.getChunksDone(),
            "only chunk 1 completed before the failure — chunksDone must stay 1");
    }

    // -----------------------------------------------------------------------
    // (e) skipHostDiscovery=true + SERVICE_DETECT: alive-host resolver is NEVER
    //     consulted; the runner gets the whole chunk CIDR (string overload —
    //     the whole-CIDR argv path already carries -Pn for port-enumerating types).
    // -----------------------------------------------------------------------

    @Test
    void skipHostDiscovery_serviceDetect_neverConsultsAliveResolver_runsWholeChunkCidr() throws Exception {
        Scan scan = stubScan(304L, "10.5.0.0/24", "SERVICE_DETECT");
        scan.setSkipHostDiscovery(true);
        when(scanRepository.findById(304L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        when(nmapRunner.run(anyString(), any(ScanType.class)))
            .thenReturn(new NmapResult(0, "stdout", ""));

        NmapOutputParser.DiscoveredHost host =
            new NmapOutputParser.DiscoveredHost("10.5.0.10", "edge", null);
        NmapOutputParser.DiscoveredService svc = new NmapOutputParser.DiscoveredService(
            "10.5.0.10", 443, "tcp", "https", "1.24.0", "nginx",
            "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*");
        when(nmapOutputParser.parse(anyString(), any(ScanType.class)))
            .thenReturn(new NmapOutputParser.ParsedScan(List.of(host), List.of(svc)));

        Device device = new Device();
        device.setId(70L);
        when(deviceUpsertService.upsert(any(), any())).thenReturn(device);
        when(networkServiceRepository.findByDeviceIdAndPortAndProtocol(70L, 443, "tcp"))
            .thenReturn(Optional.empty());

        service.executeAsync(304L);

        // The ICMP-silent path: no alive-host resolution at all.
        verify(aliveHostResolver, never()).aliveHostsIn(anyString());
        verify(nmapRunner, never()).run(anyList(), any(ScanType.class));
        // The runner is invoked with the whole chunk CIDR via the string overload.
        verify(nmapRunner).run("10.5.0.0/24", ScanType.SERVICE_DETECT);

        verify(deviceUpsertService).upsert(argThat(d -> "10.5.0.10".equals(d.ipAddress())), eq(304L));
        assertEquals(ScanStatus.COMPLETE, scan.getStatus());
    }

    // -----------------------------------------------------------------------
    // (f) skipHostDiscovery=true + SERVICE_DETECT keeps phantom suppression:
    //     a -Pn host with ZERO open services is a phantom and must NOT be upserted.
    // -----------------------------------------------------------------------

    @Test
    void skipHostDiscovery_serviceDetect_zeroServiceHostIsSuppressed() throws Exception {
        Scan scan = stubScan(305L, "10.5.1.0/24", "SERVICE_DETECT");
        scan.setSkipHostDiscovery(true);
        when(scanRepository.findById(305L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        when(nmapRunner.run(anyString(), any(ScanType.class)))
            .thenReturn(new NmapResult(0, "stdout", ""));

        // One real host (has a service) and one -Pn phantom (zero open services).
        NmapOutputParser.DiscoveredHost realHost =
            new NmapOutputParser.DiscoveredHost("10.5.1.10", "real", null);
        NmapOutputParser.DiscoveredHost phantom =
            new NmapOutputParser.DiscoveredHost("10.5.1.255", null, null);
        NmapOutputParser.DiscoveredService svc = new NmapOutputParser.DiscoveredService(
            "10.5.1.10", 22, "tcp", "ssh", "9.6p1", "OpenSSH",
            "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*");
        when(nmapOutputParser.parse(anyString(), any(ScanType.class)))
            .thenReturn(new NmapOutputParser.ParsedScan(List.of(realHost, phantom), List.of(svc)));

        Device device = new Device();
        device.setId(71L);
        when(deviceUpsertService.upsert(any(), any())).thenReturn(device);
        when(networkServiceRepository.findByDeviceIdAndPortAndProtocol(71L, 22, "tcp"))
            .thenReturn(Optional.empty());

        service.executeAsync(305L);

        verify(deviceUpsertService).upsert(argThat(d -> "10.5.1.10".equals(d.ipAddress())), eq(305L));
        verify(deviceUpsertService, never())
            .upsert(argThat(d -> "10.5.1.255".equals(d.ipAddress())), any());
        verify(deviceUpsertService, times(1)).upsert(any(), any());
        assertEquals(ScanStatus.COMPLETE, scan.getStatus());
    }

    // -----------------------------------------------------------------------
    // (g) PING_SWEEP ignores the flag — identical whole-CIDR flow.
    // -----------------------------------------------------------------------

    @Test
    void pingSweep_ignoresSkipHostDiscoveryFlag() throws Exception {
        Scan scan = stubScan(306L, "10.5.2.0/24", "PING_SWEEP");
        scan.setSkipHostDiscovery(true);
        when(scanRepository.findById(306L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        when(nmapRunner.run(anyString(), any(ScanType.class)))
            .thenReturn(new NmapResult(0, "stdout", ""));
        when(nmapOutputParser.parse(anyString(), any(ScanType.class)))
            .thenReturn(new NmapOutputParser.ParsedScan(List.of(), List.of()));

        service.executeAsync(306L);

        verify(nmapRunner).run("10.5.2.0/24", ScanType.PING_SWEEP);
        verify(aliveHostResolver, never()).aliveHostsIn(anyString());
        assertEquals(ScanStatus.COMPLETE, scan.getStatus());
    }

    // -----------------------------------------------------------------------
    // (h) OS_FINGERPRINT ignores the flag — whole-CIDR flow with OS persistence intact.
    // -----------------------------------------------------------------------

    @Test
    void osFingerprint_ignoresSkipHostDiscoveryFlag_osStillPersisted() throws Exception {
        Scan scan = stubScan(307L, "10.5.3.0/24", "OS_FINGERPRINT");
        scan.setSkipHostDiscovery(true);
        when(scanRepository.findById(307L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        when(nmapRunner.run(anyString(), any(ScanType.class)))
            .thenReturn(new NmapResult(0, "stdout", ""));

        NmapOutputParser.OsMatch osMatch =
            new NmapOutputParser.OsMatch("Linux 5.4 - 5.15", 96, "cpe:/o:linux:linux_kernel:5");
        NmapOutputParser.DiscoveredHost host =
            new NmapOutputParser.DiscoveredHost("10.5.3.9", "router", osMatch);
        when(nmapOutputParser.parse(anyString(), any(ScanType.class)))
            .thenReturn(new NmapOutputParser.ParsedScan(List.of(host), List.of()));

        Device device = new Device();
        device.setId(72L);
        when(deviceUpsertService.upsert(any(), any())).thenReturn(device);

        service.executeAsync(307L);

        verify(nmapRunner).run("10.5.3.0/24", ScanType.OS_FINGERPRINT);
        verify(aliveHostResolver, never()).aliveHostsIn(anyString());
        verify(deviceRepository).save(argThat(d -> "Linux 5.4 - 5.15".equals(d.getOsName())));
        assertEquals(ScanStatus.COMPLETE, scan.getStatus());
    }

    // -----------------------------------------------------------------------
    // (i) Resume: a re-executed scan with persisted chunksTotal=4/chunksDone=2
    //     (retry/recovery of a partially completed wide scan) runs ONLY the
    //     remaining chunks 2 and 3 and never resets chunksDone below 2.
    // -----------------------------------------------------------------------

    @Test
    void resume_chunksTotalFourDoneTwo_runsOnlyRemainingChunks_neverResetsBelowTwo() throws Exception {
        Scan scan = stubScan(308L, "10.0.0.0/20", "PING_SWEEP");
        scan.setChunksTotal(4);
        scan.setChunksDone(2);
        when(scanRepository.findById(308L)).thenReturn(Optional.of(scan));

        List<Integer> chunksDoneAtSave = new ArrayList<>();
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> {
            Scan s = inv.getArgument(0);
            chunksDoneAtSave.add(s.getChunksDone());
            return s;
        });

        when(nmapRunner.run(anyString(), any(ScanType.class)))
            .thenReturn(new NmapResult(0, "stdout", ""));
        when(nmapOutputParser.parse(anyString(), any(ScanType.class)))
            .thenReturn(new NmapOutputParser.ParsedScan(List.of(), List.of()));

        service.executeAsync(308L);

        // Only the remaining chunks (indexes 2 and 3) are run — completed chunks
        // 0 and 1 must not be re-scanned.
        verify(nmapRunner, never()).run(eq("10.0.0.0/22"), any(ScanType.class));
        verify(nmapRunner, never()).run(eq("10.0.4.0/22"), any(ScanType.class));
        verify(nmapRunner).run("10.0.8.0/22", ScanType.PING_SWEEP);
        verify(nmapRunner).run("10.0.12.0/22", ScanType.PING_SWEEP);
        verify(nmapRunner, times(2)).run(anyString(), any(ScanType.class));

        // The RUNNING seed keeps chunksDone=2 and no save ever dips below it.
        assertEquals(Integer.valueOf(2), chunksDoneAtSave.get(0),
            "RUNNING seed must preserve the resumed chunksDone, not reset to 0");
        assertThat(chunksDoneAtSave).allSatisfy(done ->
            assertThat(done).as("chunksDone must never reset below the resume point").isGreaterThanOrEqualTo(2));
        assertThat(chunksDoneAtSave).containsSubsequence(2, 3, 4);

        assertEquals(ScanStatus.COMPLETE, scan.getStatus());
        assertEquals(4, scan.getChunksTotal());
        assertEquals(4, scan.getChunksDone());
    }

    // -----------------------------------------------------------------------
    // (j) No-resume guard: a stale chunksTotal that does not match the freshly
    //     computed chunk count starts from 0 (full re-scan), as does a fresh
    //     scan with null chunksDone (pinned by test (a)).
    // -----------------------------------------------------------------------

    @Test
    void resume_staleChunksTotalMismatch_startsFromZero() throws Exception {
        Scan scan = stubScan(309L, "10.0.0.0/20", "PING_SWEEP");
        scan.setChunksTotal(8); // stale — a /20 chunks into 4, not 8
        scan.setChunksDone(2);
        when(scanRepository.findById(309L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        when(nmapRunner.run(anyString(), any(ScanType.class)))
            .thenReturn(new NmapResult(0, "stdout", ""));
        when(nmapOutputParser.parse(anyString(), any(ScanType.class)))
            .thenReturn(new NmapOutputParser.ParsedScan(List.of(), List.of()));

        service.executeAsync(309L);

        // All four chunks run — the stale progress is not trusted.
        verify(nmapRunner, times(4)).run(anyString(), any(ScanType.class));
        assertEquals(ScanStatus.COMPLETE, scan.getStatus());
        assertEquals(4, scan.getChunksTotal());
        assertEquals(4, scan.getChunksDone());
    }
}
