package io.castellum.discovery;

import io.castellum.audit.AuditService;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.risk.RiskCacheEvictor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.lang.reflect.Method;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.stream.LongStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
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
 *   <li>no stale devices → returns 0 and performs no delete / audit / cache eviction;</li>
 *   <li>stale devices → bulk-deleted via {@code deleteAllByIdInBatch} (never one-by-one),
 *       exactly ONE audit event (actor {@code "scheduler"}, action {@code "DEVICE_PRUNE"}),
 *       exactly one {@code riskCacheEvictor.onDevicesPruned()}, returns pruned count;</li>
 *   <li>the audit payload id list is capped at 50 entries while the count reflects all.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class DevicePruneServiceTest {

    private static final Instant NOW = Instant.parse("2026-06-12T03:30:00Z");
    private static final Duration TTL = Duration.ofDays(14);
    private static final Instant EXPECTED_CUTOFF = Instant.parse("2026-05-29T03:30:00Z");

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
            TTL);
    }

    @Test
    void prune_queriesFinder_withPublicScope_andExactClockMinusTtlCutoff() {
        when(deviceRepository.findIdsByDiscoveryScopeAndLastSeenBefore(eq(DiscoveryScope.PUBLIC), any()))
            .thenReturn(List.of());

        service.pruneStalePublicDevices();

        // Fixed clock 2026-06-12T03:30:00Z minus P14D — the EXACT cutoff, no Instant.now() drift.
        verify(deviceRepository)
            .findIdsByDiscoveryScopeAndLastSeenBefore(DiscoveryScope.PUBLIC, EXPECTED_CUTOFF);
    }

    @Test
    void prune_noStaleDevices_returnsZero_noDelete_noAudit_noEviction() {
        when(deviceRepository.findIdsByDiscoveryScopeAndLastSeenBefore(eq(DiscoveryScope.PUBLIC), any()))
            .thenReturn(List.of());

        int pruned = service.pruneStalePublicDevices();

        assertThat(pruned).isZero();
        verify(deviceRepository)
            .findIdsByDiscoveryScopeAndLastSeenBefore(DiscoveryScope.PUBLIC, EXPECTED_CUTOFF);
        // Empty sweep must be a true no-op: no delete of any flavour, no audit row, no eviction.
        verifyNoMoreInteractions(deviceRepository);
        verifyNoInteractions(auditService, riskCacheEvictor);
    }

    @Test
    void prune_staleDevices_bulkDeletesViaDeleteAllByIdInBatch_notOneByOne() {
        List<Long> staleIds = List.of(11L, 12L, 13L);
        when(deviceRepository.findIdsByDiscoveryScopeAndLastSeenBefore(eq(DiscoveryScope.PUBLIC), any()))
            .thenReturn(staleIds);

        int pruned = service.pruneStalePublicDevices();

        assertThat(pruned).isEqualTo(3);
        verify(deviceRepository, times(1)).deleteAllByIdInBatch(staleIds);
        // Pin bulk semantics — N round-trips per device is the failure mode being designed out.
        verify(deviceRepository, never()).deleteById(anyLong());
        verify(deviceRepository, never()).delete(any(Device.class));
    }

    @Test
    void prune_staleDevices_recordsExactlyOneAuditEvent_actorScheduler_actionDevicePrune() {
        when(deviceRepository.findIdsByDiscoveryScopeAndLastSeenBefore(eq(DiscoveryScope.PUBLIC), any()))
            .thenReturn(List.of(11L, 12L, 13L));

        service.pruneStalePublicDevices();

        ArgumentCaptor<Object> payloadCaptor = ArgumentCaptor.forClass(Object.class);
        verify(auditService, times(1)).recordEvent(
            eq("scheduler"), eq("DEVICE_PRUNE"), any(), any(), payloadCaptor.capture());
        verifyNoMoreInteractions(auditService);

        // Payload contract (keys the GREEN implementation must use): "count" + "deviceIds".
        assertThat(payloadCaptor.getValue()).isInstanceOf(Map.class);
        Map<?, ?> payload = (Map<?, ?>) payloadCaptor.getValue();
        assertThat(((Number) payload.get("count")).intValue()).isEqualTo(3);
        @SuppressWarnings("unchecked")
        List<Long> reportedIds = (List<Long>) payload.get("deviceIds");
        assertThat(reportedIds).containsExactly(11L, 12L, 13L);
    }

    @Test
    void prune_staleDevices_evictsRiskCachesExactlyOnce() {
        when(deviceRepository.findIdsByDiscoveryScopeAndLastSeenBefore(eq(DiscoveryScope.PUBLIC), any()))
            .thenReturn(List.of(11L));

        service.pruneStalePublicDevices();

        verify(riskCacheEvictor, times(1)).onDevicesPruned();
        verifyNoMoreInteractions(riskCacheEvictor);
    }

    @Test
    void prune_sixtyStaleDevices_auditIdListCappedAt50_countReflectsAll60() {
        List<Long> staleIds = LongStream.rangeClosed(1, 60).boxed().toList();
        when(deviceRepository.findIdsByDiscoveryScopeAndLastSeenBefore(eq(DiscoveryScope.PUBLIC), any()))
            .thenReturn(staleIds);

        int pruned = service.pruneStalePublicDevices();

        assertThat(pruned).isEqualTo(60);
        verify(deviceRepository).deleteAllByIdInBatch(staleIds);

        ArgumentCaptor<Object> payloadCaptor = ArgumentCaptor.forClass(Object.class);
        verify(auditService, times(1)).recordEvent(
            eq("scheduler"), eq("DEVICE_PRUNE"), any(), any(), payloadCaptor.capture());

        Map<?, ?> payload = (Map<?, ?>) payloadCaptor.getValue();
        assertThat(((Number) payload.get("count")).intValue())
            .as("count must reflect ALL pruned devices")
            .isEqualTo(60);
        @SuppressWarnings("unchecked")
        List<Long> reportedIds = (List<Long>) payload.get("deviceIds");
        assertThat(reportedIds)
            .as("audit payload id list must be capped at 50 entries")
            .hasSize(50);
        assertThat(reportedIds).isSubsetOf(staleIds);
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
