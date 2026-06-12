package io.castellum.discovery;

import io.castellum.audit.AuditService;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.risk.Criticality;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Validates the Phase D.1 fix to {@link MdnsProbe}:
 * <ol>
 *   <li>{@code info.getServer()} no longer overwrites the IP field.</li>
 *   <li>The captured hostname now flows through the {@link DiscoveredNeighbor} 6th field.</li>
 *   <li>{@code Device.hostname} lands non-null after upsert when an mDNS source provided one.</li>
 * </ol>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MdnsProbeHostnamePropagationTest {

    @Mock private ArpReaderFactory arpFactory;
    @Mock private ArpReader arpReader;
    @Mock private MdnsProbe mdnsProbe;
    @Mock private PcapSniffer pcapSniffer;
    @Mock private LldpDecoder lldpDecoder;
    @Mock private LldpCapture lldpCapture;
    @Mock private CdpDecoder cdpDecoder;
    @Mock private ConnTableReader connTableReader;
    @Mock private GatewayProbe gatewayProbe;
    @Mock private AuditService auditService;
    @Mock private DiscoverySweepRecorder recorder;
    @Mock private DeviceRepository deviceRepository;

    private DeviceUpsertService realUpsert;
    private PassiveDiscoveryService service;
    private Clock clock;

    @BeforeEach
    void setUp() {
        clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        realUpsert = new DeviceUpsertService(deviceRepository, new DiscoveryScopeClassifier(), new DeviceRoleClassifier());
        service = new PassiveDiscoveryService(
            arpFactory, mdnsProbe, pcapSniffer, lldpDecoder, lldpCapture, cdpDecoder,
            connTableReader, gatewayProbe,
            realUpsert, auditService, recorder,
            false, false, true, true, clock);
        when(recorder.start(anyString(), any(), anyString())).thenReturn(7L);
        // Saved devices echo back with sequential IDs
        when(deviceRepository.findByIpAddress(anyString())).thenReturn(Optional.empty());
        when(deviceRepository.findByIpAddressIn(anyList())).thenReturn(List.of());
        when(deviceRepository.saveAll(anyList())).thenAnswer(inv -> {
            List<Device> in = inv.getArgument(0);
            long id = 1L;
            for (Device d : in) d.setId(id++);
            return new ArrayList<>(in);
        });
    }

    @Test
    void serviceResolved_withIpv4AndServer_neighborCarriesHostname() {
        DiscoveredNeighbor n = MdnsProbe.buildNeighbor("192.168.1.50", "host.local.");

        assertThat(n).isNotNull();
        assertThat(n.ipAddress()).isEqualTo("192.168.1.50");
        assertThat(n.hostname()).isEqualTo("host.local.");
    }

    @Test
    void serviceResolved_withoutIpv4_doesNotPlaceHostnameInIpField() {
        DiscoveredNeighbor n = MdnsProbe.buildNeighbor(null, "orphan.local.");

        assertThat(n).isNotNull();
        assertThat(n.ipAddress()).isNull();
        assertThat(n.hostname()).isEqualTo("orphan.local.");
    }

    @Test
    void serviceResolved_withoutIpv4OrHostname_returnsNull() {
        assertThat(MdnsProbe.buildNeighbor(null, null)).isNull();
        assertThat(MdnsProbe.buildNeighbor(null, "  ")).isNull();
    }

    @Test
    void endToEnd_mdnsDiscoveredDevice_hostnameNonNullAfterUpsert() throws Exception {
        when(mdnsProbe.probe(anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor("192.168.1.50", null, null, null, null, "host.local.")
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(null, 5, List.of(DiscoverySource.MDNS));
        service.sweep(req);

        ArgumentCaptor<List<Device>> cap = ArgumentCaptor.forClass(List.class);
        verify(deviceRepository, times(1)).saveAll(cap.capture());
        // saveAll may be called twice (updates + inserts) — we want the inserts list (size>0).
        Device saved = cap.getAllValues().stream()
            .flatMap(List::stream)
            .filter(d -> "192.168.1.50".equals(d.getIpAddress()))
            .findFirst().orElseThrow();
        assertThat(saved.getHostname()).isEqualTo("host.local.");
        assertThat(saved.getCriticality()).isEqualTo(Criticality.MEDIUM);
    }
}
