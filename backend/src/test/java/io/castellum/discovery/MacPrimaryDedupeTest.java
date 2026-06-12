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
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * MAC-primary dedupe behaviour. Two layers:
 * <ol>
 *   <li><b>Aggregate-side</b> ({@link PassiveDiscoveryService}): rows with a MAC dedupe by MAC,
 *       rows without fall back to IP key.</li>
 *   <li><b>Persist-side</b> ({@link DeviceUpsertService}): existing devices match by MAC first,
 *       then by IP for the IP-only partition.</li>
 * </ol>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MacPrimaryDedupeTest {

    @Mock private ArpReaderFactory arpFactory;
    @Mock private ArpReader arpReader;
    @Mock private MdnsProbe mdnsProbe;
    @Mock private PcapSniffer pcapSniffer;
    @Mock private LldpDecoder lldpDecoder;
    @Mock private CdpDecoder cdpDecoder;
    @Mock private ConnTableReader connTableReader;
    @Mock private GatewayProbe gatewayProbe;
    @Mock private AuditService auditService;
    @Mock private DiscoverySweepRecorder recorder;
    @Mock private DeviceRepository deviceRepository;

    private PassiveDiscoveryService service;
    private DeviceUpsertService upsertService;

    @BeforeEach
    void setUp() {
        Clock clock = Clock.fixed(Instant.parse("2026-04-30T00:00:00Z"), ZoneOffset.UTC);
        upsertService = new DeviceUpsertService(deviceRepository, new DiscoveryScopeClassifier(), new DeviceRoleClassifier());
        service = new PassiveDiscoveryService(
            arpFactory, mdnsProbe, pcapSniffer, lldpDecoder, cdpDecoder,
            connTableReader, gatewayProbe,
            upsertService, auditService, recorder,
            false, false, true, true, clock);
        when(arpFactory.select()).thenReturn(arpReader);
        when(recorder.start(anyString(), any(), anyString())).thenReturn(99L);
        when(deviceRepository.findByIpAddressIn(anyList())).thenReturn(List.of());
        when(deviceRepository.findByMacAddressIn(anyList())).thenReturn(List.of());
        when(deviceRepository.saveAll(anyList())).thenAnswer(inv -> {
            List<Device> in = inv.getArgument(0);
            long id = 1L;
            for (Device d : in) {
                if (d.getId() == null) d.setId(id++);
            }
            return new ArrayList<>(in);
        });
    }

    @Test
    void aggregate_sameMacDifferentIps_collapseToSingleDiscovery() throws Exception {
        // Same NIC observed at two different IPs (renumber event mid-sweep).
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.0.1", "aa:bb:cc:dd:ee:ff", "0x1", "0x2", "eth0", null),
            new DiscoveredNeighbor("10.0.0.99", "aa:bb:cc:dd:ee:ff", "0x1", "0x2", "eth0", null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.ARP));
        PassiveDiscoveryResponse resp = service.sweep(req);

        assertThat(resp.discovered()).isEqualTo(1);
    }

    @Test
    void aggregate_noMac_fallsBackToIpKey() throws Exception {
        // No MAC → IP-key dedupe path
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.1.1", null, null, null, null, null),
            new DiscoveredNeighbor("10.0.1.1", null, null, null, null, null),
            new DiscoveredNeighbor("10.0.1.2", null, null, null, null, null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.ARP));
        PassiveDiscoveryResponse resp = service.sweep(req);

        assertThat(resp.discovered()).isEqualTo(2);
    }

    @Test
    void upsertAll_existingDeviceMatchedByMac_updatesIpAddress() {
        // An existing device row with old IP but the same MAC — upsertAll should reuse the row
        // and update ipAddress, NOT insert a new row.
        Device existing = new Device(7L, "10.0.0.1", null, "aa:bb:cc:dd:ee:ff",
            Instant.parse("2026-04-29T00:00:00Z"), Instant.parse("2026-04-29T12:00:00Z"),
            Criticality.MEDIUM);
        when(deviceRepository.findByMacAddressIn(any(Collection.class))).thenReturn(List.of(existing));

        Discovery freshObservation = new Discovery("10.0.0.99", "aa:bb:cc:dd:ee:ff", null,
            DiscoverySource.ARP, Instant.parse("2026-04-30T00:00:00Z"), null, false);

        upsertService.upsertAll(List.of(freshObservation));

        ArgumentCaptor<List<Device>> cap = ArgumentCaptor.forClass(List.class);
        verify(deviceRepository).saveAll(cap.capture());
        Device saved = cap.getValue().get(0);
        assertThat(saved.getId()).isEqualTo(7L);
        assertThat(saved.getIpAddress()).isEqualTo("10.0.0.99");
        assertThat(saved.getMacAddress()).isEqualTo("aa:bb:cc:dd:ee:ff");
    }

    @Test
    void upsertAll_emptyMacPartition_skipsMacLookup() {
        // No MAC-bearing discoveries → findByMacAddressIn must NOT be called.
        Discovery ipOnly = new Discovery("10.0.2.1", null, null, DiscoverySource.MDNS,
            Instant.parse("2026-04-30T00:00:00Z"), null, false);

        upsertService.upsertAll(List.of(ipOnly));

        verify(deviceRepository, never()).findByMacAddressIn(any(Collection.class));
        verify(deviceRepository, times(1)).findByIpAddressIn(any(Collection.class));
    }
}
