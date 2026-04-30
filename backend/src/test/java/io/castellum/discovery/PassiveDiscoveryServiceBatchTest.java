package io.castellum.discovery;

import io.castellum.audit.AuditService;
import io.castellum.domain.Device;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Verifies that {@link PassiveDiscoveryService#sweep} calls the batch
 * {@link DeviceUpsertService#upsertAll} entry point exactly once and never falls back
 * to the per-event {@link DeviceUpsertService#upsert} call site after the batch wiring.
 *
 * <p>Pure Mockito (no Spring context) — see Task D.1 for the lightening pattern.
 */
@ExtendWith(MockitoExtension.class)
class PassiveDiscoveryServiceBatchTest {

    @Mock private ArpCacheReader arpReader;
    @Mock private MdnsProbe mdnsProbe;
    @Mock private PcapSniffer pcapSniffer;
    @Mock private LldpDecoder lldpDecoder;
    @Mock private CdpDecoder cdpDecoder;
    @Mock private DeviceUpsertService upsertService;
    @Mock private AuditService auditService;

    private final Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);

    private PassiveDiscoveryService service() {
        return new PassiveDiscoveryService(arpReader, mdnsProbe, pcapSniffer,
            lldpDecoder, cdpDecoder, upsertService, auditService, false, false, clock);
    }

    @Test
    void sweep_with100UniqueArpNeighbors_callsSaveAllOnceAndFindByIpAddressInOnce() {
        List<DiscoveredNeighbor> neighbors = new ArrayList<>(100);
        for (int i = 0; i < 100; i++) {
            neighbors.add(new DiscoveredNeighbor("10.0.0." + i,
                String.format("aa:bb:cc:dd:ee:%02x", i), "0x1", "0x2", "eth0"));
        }
        when(arpReader.read()).thenReturn(neighbors);
        when(upsertService.upsertAll(anyList())).thenAnswer(inv -> {
            List<Discovery> in = inv.getArgument(0);
            List<Device> out = new ArrayList<>(in.size());
            long id = 1L;
            for (Discovery d : in) {
                Device dev = new Device();
                dev.setId(id++);
                dev.setIpAddress(d.ipAddress());
                out.add(dev);
            }
            return out;
        });

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.ARP));
        PassiveDiscoveryResponse resp = service().sweep(req);

        assertThat(resp.discovered()).isEqualTo(100);
        assertThat(resp.deviceIds()).hasSize(100);
        verify(upsertService, times(1)).upsertAll(anyList());
    }

    @Test
    void sweep_with100UniqueArpNeighbors_neverCallsPerEventSaveOrFindByIpAddress() {
        List<DiscoveredNeighbor> neighbors = new ArrayList<>(100);
        for (int i = 0; i < 100; i++) {
            neighbors.add(new DiscoveredNeighbor("10.1.0." + i,
                String.format("bb:cc:dd:ee:ff:%02x", i), "0x1", "0x2", "eth0"));
        }
        when(arpReader.read()).thenReturn(neighbors);
        when(upsertService.upsertAll(anyList())).thenAnswer(inv -> {
            List<Discovery> in = inv.getArgument(0);
            List<Device> out = new ArrayList<>(in.size());
            long id = 1L;
            for (Discovery d : in) {
                Device dev = new Device();
                dev.setId(id++);
                dev.setIpAddress(d.ipAddress());
                out.add(dev);
            }
            return out;
        });

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.ARP));
        service().sweep(req);

        verify(upsertService, never()).upsert(any(Discovery.class));
    }

    @Test
    void sweep_emptyDiscoveries_skipsRepositoryEntirely() {
        when(arpReader.read()).thenReturn(List.of());

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.ARP));
        PassiveDiscoveryResponse resp = service().sweep(req);

        assertThat(resp.discovered()).isEqualTo(0);
        assertThat(resp.deviceIds()).isEmpty();
        verifyNoInteractions(upsertService);
    }
}
