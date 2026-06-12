package io.castellum.discovery;

import io.castellum.audit.AuditService;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.DeviceRepository.StaleDeviceSample;
import io.castellum.risk.RiskCacheEvictor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.lang.reflect.Method;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.stream.LongStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

/**
 * Specifies {@link DevicePruneService#pruneStalePublicDevices()} — the PUBLIC-scope device
 * TTL retention job:
 * <ul>
 *   <li>cutoff is {@code clock.instant().minus(ttl)} — pinned with a fixed Clock;</li>
 *   <li>the prune is ONE atomic predicate delete ({@code deleteStaleByScopeAndSources}
 *       with the {@code PRUNABLE_SOURCES} allowlist) — never find-then-delete-by-id;</li>
 *   <li>delete count 0 → returns 0, no audit, no cache eviction (gated on the DELETE's own
 *       row count, not the pre-delete sample);</li>
 *   <li>delete count &gt; 0 → exactly ONE audit event (actor {@code "scheduler"}, action
 *       {@code "DEVICE_PRUNE"}, resourceType {@code "device"}, resourceId {@code "-"})
 *       whose payload carries count, cutoff, ttl, sampleSize, and the capped identity
 *       sample; exactly one {@code riskCacheEvictor.onDevicesPruned()};</li>
 *   <li>the constructor parses the TTL strictly as ISO-8601 (bare numbers and Spring
 *       simple-style values are rejected outright) and enforces the PT1H floor.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class DevicePruneServiceTest {

    private static final Instant NOW = Instant.parse("2026-06-12T03:30:00Z");
    private static final String TTL_VALUE = "P14D";
    private static final Duration TTL = Duration.ofDays(14);
    private static final Instant EXPECTED_CUTOFF = Instant.parse("2026-05-29T03:30:00Z");
    private static final Pageable EXPECTED_SAMPLE_PAGE = PageRequest.of(0, 50, Sort.by("lastSeen"));

    @Mock private DeviceRepository deviceRepository;
    @Mock private AuditService auditService;
    @Mock private RiskCacheEvictor riskCacheEvictor;

    private DevicePruneService service;

    @BeforeEach
    void setUp() {
        service = new DevicePruneService(
            deviceRepository,
            auditService,
            riskCacheEvictor,
            Clock.fixed(NOW, ZoneOffset.UTC),
            TTL_VALUE);
    }

    private static StaleDeviceSample sample(long id, String ip, String originHostIp, Instant lastSeen) {
        return new StaleDeviceSample() {
            @Override public Long getId() { return id; }
            @Override public String getIpAddress() { return ip; }
            @Override public String getOriginHostIp() { return originHostIp; }
            @Override public Instant getLastSeen() { return lastSeen; }
        };
    }

    @Test
    void prune_runsPredicateDelete_withPublicScope_exactCutoff_andSourceAllowlist() {
        when(deviceRepository.deleteStaleByScopeAndSources(eq(DiscoveryScope.PUBLIC), any(), any()))
            .thenReturn(0);

        service.pruneStalePublicDevices();

        // Fixed clock 2026-06-12T03:30:00Z minus P14D — the EXACT cutoff, no Instant.now() drift.
        verify(deviceRepository).deleteStaleByScopeAndSources(
            DiscoveryScope.PUBLIC, EXPECTED_CUTOFF, DevicePruneService.PRUNABLE_SOURCES);
        // The pre-delete identity sample queries the SAME predicate, capped at 50.
        verify(deviceRepository).findStaleSamplesByScopeAndSources(
            DiscoveryScope.PUBLIC, EXPECTED_CUTOFF, DevicePruneService.PRUNABLE_SOURCES,
            EXPECTED_SAMPLE_PAGE);
    }

    @Test
    void prunableSources_excludeScanProbeDockerSources() {
        // The allowlist is the layer that keeps deliberately scanned/probed assets and
        // container inventory out of TTL pruning — pin its contents.
        assertThat(DevicePruneService.PRUNABLE_SOURCES).containsExactlyInAnyOrder(
            DiscoverySource.ARP, DiscoverySource.MDNS, DiscoverySource.PCAP,
            DiscoverySource.LLDP, DiscoverySource.CDP, DiscoverySource.CONN_TABLE,
            DiscoverySource.GATEWAY);
        assertThat(DevicePruneService.PRUNABLE_SOURCES).doesNotContain(
            DiscoverySource.NMAP_SCAN, DiscoverySource.OT_PROBE, DiscoverySource.DOCKER);
    }

    @Test
    void prune_noStaleDevices_returnsZero_noAudit_noEviction() {
        when(deviceRepository.deleteStaleByScopeAndSources(eq(DiscoveryScope.PUBLIC), any(), any()))
            .thenReturn(0);

        int pruned = service.pruneStalePublicDevices();

        assertThat(pruned).isZero();
        verify(deviceRepository).deleteStaleByScopeAndSources(
            DiscoveryScope.PUBLIC, EXPECTED_CUTOFF, DevicePruneService.PRUNABLE_SOURCES);
        verify(deviceRepository).findStaleSamplesByScopeAndSources(
            eq(DiscoveryScope.PUBLIC), eq(EXPECTED_CUTOFF), eq(DevicePruneService.PRUNABLE_SOURCES),
            any(Pageable.class));
        // Empty sweep must otherwise be a true no-op: no other deletes, no audit row, no eviction.
        verifyNoMoreInteractions(deviceRepository);
        verifyNoInteractions(auditService, riskCacheEvictor);
    }

    @Test
    void prune_gatesOnDeleteCount_notOnSample_raceEmptiesSetAfterSample() {
        // The sample saw rows, but a concurrent refresh emptied the stale set before the
        // DELETE ran — the DELETE count is the authority, so the run stays a no-op.
        when(deviceRepository.findStaleSamplesByScopeAndSources(
                eq(DiscoveryScope.PUBLIC), any(), any(), any(Pageable.class)))
            .thenReturn(List.of(sample(11L, "203.0.113.10", "local", EXPECTED_CUTOFF.minusSeconds(60))));
        when(deviceRepository.deleteStaleByScopeAndSources(eq(DiscoveryScope.PUBLIC), any(), any()))
            .thenReturn(0);

        int pruned = service.pruneStalePublicDevices();

        assertThat(pruned).isZero();
        verifyNoInteractions(auditService, riskCacheEvictor);
    }

    @Test
    void prune_staleDevices_singlePredicateDelete_neverOneByOne_neverIdList() {
        when(deviceRepository.deleteStaleByScopeAndSources(eq(DiscoveryScope.PUBLIC), any(), any()))
            .thenReturn(3);

        int pruned = service.pruneStalePublicDevices();

        assertThat(pruned).isEqualTo(3);
        verify(deviceRepository, times(1)).deleteStaleByScopeAndSources(
            DiscoveryScope.PUBLIC, EXPECTED_CUTOFF, DevicePruneService.PRUNABLE_SOURCES);
        // Pin bulk semantics — per-row round-trips and id-list deletes are the failure
        // modes being designed out (TOCTOU + bind-parameter cliff).
        verify(deviceRepository, never()).deleteById(anyLong());
        verify(deviceRepository, never()).delete(any(Device.class));
        verify(deviceRepository, never()).deleteAllByIdInBatch(any());
    }

    @Test
    void prune_staleDevices_recordsExactlyOneAuditEvent_withFullForensicPayload() {
        Instant lastSeenA = Instant.parse("2026-05-01T00:00:00Z");
        Instant lastSeenB = Instant.parse("2026-05-02T00:00:00Z");
        when(deviceRepository.findStaleSamplesByScopeAndSources(
                eq(DiscoveryScope.PUBLIC), any(), any(), any(Pageable.class)))
            .thenReturn(List.of(
                sample(11L, "203.0.113.10", "local", lastSeenA),
                sample(12L, "203.0.113.11", "192.0.2.7", lastSeenB)));
        when(deviceRepository.deleteStaleByScopeAndSources(eq(DiscoveryScope.PUBLIC), any(), any()))
            .thenReturn(2);

        service.pruneStalePublicDevices();

        ArgumentCaptor<Object> payloadCaptor = ArgumentCaptor.forClass(Object.class);
        verify(auditService, times(1)).recordEvent(
            eq("scheduler"), eq("DEVICE_PRUNE"), eq("device"), eq("-"), payloadCaptor.capture());
        verifyNoMoreInteractions(auditService);

        // Payload contract: count + cutoff + ttl + sampleSize + identity sample — the hard
        // delete destroys the identity tuple, so the audit row must carry it.
        assertThat(payloadCaptor.getValue()).isInstanceOf(Map.class);
        Map<?, ?> payload = (Map<?, ?>) payloadCaptor.getValue();
        assertThat(((Number) payload.get("count")).intValue()).isEqualTo(2);
        assertThat(payload.get("cutoff")).isEqualTo(EXPECTED_CUTOFF.toString());
        assertThat(payload.get("ttl")).isEqualTo(TTL.toString());
        assertThat(((Number) payload.get("sampleSize")).intValue()).isEqualTo(2);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> reportedSample = (List<Map<String, Object>>) payload.get("sample");
        assertThat(reportedSample).containsExactly(
            Map.of("id", 11L, "ipAddress", "203.0.113.10", "originHostIp", "local",
                   "lastSeen", lastSeenA.toString()),
            Map.of("id", 12L, "ipAddress", "203.0.113.11", "originHostIp", "192.0.2.7",
                   "lastSeen", lastSeenB.toString()));
    }

    @Test
    void prune_samplesIdentityBeforeDelete_orderingIsLoadBearing() {
        when(deviceRepository.deleteStaleByScopeAndSources(eq(DiscoveryScope.PUBLIC), any(), any()))
            .thenReturn(1);

        service.pruneStalePublicDevices();

        // Reversed, the sample query would match zero rows post-delete and every audit
        // event would carry an empty sample — the order is part of the contract.
        InOrder inOrder = inOrder(deviceRepository);
        inOrder.verify(deviceRepository).findStaleSamplesByScopeAndSources(
            eq(DiscoveryScope.PUBLIC), eq(EXPECTED_CUTOFF), eq(DevicePruneService.PRUNABLE_SOURCES),
            any(Pageable.class));
        inOrder.verify(deviceRepository).deleteStaleByScopeAndSources(
            DiscoveryScope.PUBLIC, EXPECTED_CUTOFF, DevicePruneService.PRUNABLE_SOURCES);
    }

    @Test
    void prune_staleDevices_evictsRiskCachesExactlyOnce() {
        when(deviceRepository.deleteStaleByScopeAndSources(eq(DiscoveryScope.PUBLIC), any(), any()))
            .thenReturn(1);

        // No transaction synchronization is active in a plain unit test, so the eviction
        // runs inline; under a live transaction it is deferred to afterCommit.
        service.pruneStalePublicDevices();

        verify(riskCacheEvictor, times(1)).onDevicesPruned();
        verifyNoMoreInteractions(riskCacheEvictor);
    }

    @Test
    void prune_activeSynchronization_defersEvictionToAfterCommit_exactlyOnce() {
        when(deviceRepository.deleteStaleByScopeAndSources(eq(DiscoveryScope.PUBLIC), any(), any()))
            .thenReturn(2);

        // Spring's @Transactional proxy always activates synchronization in production, so
        // the afterCommit registration is the only branch a deployed instance ever takes.
        TransactionSynchronizationManager.initSynchronization();
        try {
            service.pruneStalePublicDevices();

            // Eviction must wait for the commit — an in-transaction eviction lets a
            // concurrent reader repopulate the caches from the pre-delete snapshot.
            verify(riskCacheEvictor, never()).onDevicesPruned();

            for (TransactionSynchronization synchronization
                    : TransactionSynchronizationManager.getSynchronizations()) {
                synchronization.afterCommit();
            }

            verify(riskCacheEvictor, times(1)).onDevicesPruned();
            verifyNoMoreInteractions(riskCacheEvictor);
        } finally {
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    @Test
    void prune_activeSynchronization_noOpRun_registersNoSynchronization() {
        when(deviceRepository.deleteStaleByScopeAndSources(eq(DiscoveryScope.PUBLIC), any(), any()))
            .thenReturn(0);

        TransactionSynchronizationManager.initSynchronization();
        try {
            service.pruneStalePublicDevices();

            // An empty sweep must not even enqueue a deferred eviction.
            assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
            verifyNoInteractions(riskCacheEvictor);
        } finally {
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    @Test
    void prune_countAboveCap_sampleIsPartial_countReflectsAll() {
        List<StaleDeviceSample> cappedSample = LongStream.rangeClosed(1, 50)
            .mapToObj(i -> sample(i, "203.0.113." + i, "local", EXPECTED_CUTOFF.minusSeconds(i)))
            .toList();
        when(deviceRepository.findStaleSamplesByScopeAndSources(
                eq(DiscoveryScope.PUBLIC), any(), any(), any(Pageable.class)))
            .thenReturn(cappedSample);
        when(deviceRepository.deleteStaleByScopeAndSources(eq(DiscoveryScope.PUBLIC), any(), any()))
            .thenReturn(60);

        int pruned = service.pruneStalePublicDevices();

        assertThat(pruned).isEqualTo(60);
        ArgumentCaptor<Object> payloadCaptor = ArgumentCaptor.forClass(Object.class);
        verify(auditService, times(1)).recordEvent(
            eq("scheduler"), eq("DEVICE_PRUNE"), eq("device"), eq("-"), payloadCaptor.capture());

        Map<?, ?> payload = (Map<?, ?>) payloadCaptor.getValue();
        assertThat(((Number) payload.get("count")).intValue())
            .as("count must reflect ALL pruned devices")
            .isEqualTo(60);
        assertThat(((Number) payload.get("sampleSize")).intValue())
            .as("sampleSize must expose that the sample is partial when count > 50")
            .isEqualTo(50);
        assertThat((List<?>) payload.get("sample"))
            .as("audit payload identity sample must be capped at 50 entries")
            .hasSize(50);
    }

    private DevicePruneService construct(String ttlValue) {
        return new DevicePruneService(
            deviceRepository, auditService, riskCacheEvictor,
            Clock.fixed(NOW, ZoneOffset.UTC), ttlValue);
    }

    @Test
    void constructor_rejectsBareNumberTtl_namingPropertyEnvVarValueAndFormat() {
        // A bare "14" is not ISO-8601 — the strict parse turns the misconfiguration into a
        // boot failure instead of binding it as 14 milliseconds.
        assertThatThrownBy(() -> construct("14"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("castellum.discovery.public-device-prune.ttl")
            .hasMessageContaining("DISCOVERY_PUBLIC_DEVICE_TTL")
            .hasMessageContaining("14")
            .hasMessageContaining("ISO-8601")
            .hasMessageContaining("P14D");
    }

    @Test
    void constructor_rejectsLargeBareNumberTtl_thePreviouslySilentKiller() {
        // 31536000 (an operator intending seconds = 365 days) would bind as ~8.76 hours
        // under lenient millisecond conversion and clear the PT1H floor — the strict parse
        // must reject it outright.
        assertThatThrownBy(() -> construct("31536000"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("castellum.discovery.public-device-prune.ttl")
            .hasMessageContaining("DISCOVERY_PUBLIC_DEVICE_TTL")
            .hasMessageContaining("31536000")
            .hasMessageContaining("ISO-8601");
    }

    @Test
    void constructor_rejectsSpringSimpleStyleTtl() {
        // "30d" is Spring simple-style, not ISO-8601 — strict parsing rejects it too.
        assertThatThrownBy(() -> construct("30d"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("castellum.discovery.public-device-prune.ttl")
            .hasMessageContaining("DISCOVERY_PUBLIC_DEVICE_TTL")
            .hasMessageContaining("30d")
            .hasMessageContaining("ISO-8601");
    }

    @Test
    void constructor_rejectsValidIsoTtlBelowOneHourFloor() {
        // PT30M parses fine but sits below the PT1H floor — still a boot failure.
        assertThatThrownBy(() -> construct("PT30M"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("castellum.discovery.public-device-prune.ttl")
            .hasMessageContaining("DISCOVERY_PUBLIC_DEVICE_TTL")
            .hasMessageContaining("PT1H");
    }

    @Test
    void constructor_rejectsNegativeTtl() {
        // A negative duration parses but is below the floor.
        assertThatThrownBy(() -> construct("-P14D"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("PT1H");
    }

    @Test
    void constructor_acceptsOneHourFloorAndDefault() {
        assertThatCode(() -> construct("PT1H")).doesNotThrowAnyException();
        assertThatCode(() -> construct("P14D")).doesNotThrowAnyException();
    }

    @Test
    void pruneStalePublicDevices_isTransactional_andServiceIsSpringBean() throws Exception {
        // JPQL bulk delete requires an active transaction; @Service makes the @Value TTL bindable.
        assertThat(DevicePruneService.class.isAnnotationPresent(Service.class))
            .as("DevicePruneService must be a @Service bean")
            .isTrue();
        Method prune = DevicePruneService.class.getMethod("pruneStalePublicDevices");
        assertThat(prune.isAnnotationPresent(Transactional.class))
            .as("pruneStalePublicDevices must be @Transactional")
            .isTrue();
    }
}
