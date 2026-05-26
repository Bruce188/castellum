package io.castellum.discovery;

import io.castellum.audit.AuditService;
import io.castellum.domain.Device;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Plain Mockito version of the discovery sweep tests. Was previously
 * {@code @SpringBootTest} which spun up the full Spring context (~3s startup).
 * Behaviour-identical assertions; switching to {@link MockitoExtension} drops
 * the suite to under 500ms.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PassiveDiscoveryServiceTest {

    @Mock private ArpReaderFactory arpFactory;
    @Mock private ArpReader arpReader;
    @Mock private MdnsProbe mdnsProbe;
    @Mock private PcapSniffer pcapSniffer;
    @Mock private LldpDecoder lldpDecoder;
    @Mock private CdpDecoder cdpDecoder;
    @Mock private DeviceUpsertService upsertService;
    @Mock private AuditService auditService;
    @Mock private DiscoverySweepRecorder recorder;

    private PassiveDiscoveryService service;
    private Clock clock;

    @BeforeEach
    void setUp() {
        clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        service = new PassiveDiscoveryService(
            arpFactory, mdnsProbe, pcapSniffer, lldpDecoder, cdpDecoder,
            upsertService, auditService, recorder,
            false /* lldpEnabled */,
            false /* cdpEnabled */,
            true /* pcapEnabled — existing PCAP cases assume enabled */,
            clock
        );
        when(arpFactory.select()).thenReturn(arpReader);
        when(recorder.start(anyString(), any(), anyString())).thenReturn(42L);
        // upsertAll returns one Device per Discovery, with sequential ids — preserves input order
        when(upsertService.upsertAll(anyList())).thenAnswer(inv -> {
            List<Discovery> in = inv.getArgument(0);
            List<Device> out = new ArrayList<>(in.size());
            long next = 1L;
            for (Discovery d : in) {
                out.add(new Device(next++, d.ipAddress(), d.hostname(), d.macAddress(),
                    d.observedAt(), d.observedAt(), Criticality.MEDIUM));
            }
            return out;
        });
        when(auditService.recordEvent(any(), any(), any(), any(), any())).thenReturn(null);
    }

    @Test
    void sweep_arpOnly_callsUpsertPerNeighbor() throws Exception {
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.0.1", "aa:00:00:00:00:01", "0x1", "0x2", "eth0", null),
            new DiscoveredNeighbor("10.0.0.2", "aa:00:00:00:00:02", "0x1", "0x2", "eth0", null),
            new DiscoveredNeighbor("10.0.0.3", "aa:00:00:00:00:03", "0x1", "0x2", "eth0", null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.ARP));
        PassiveDiscoveryResponse resp = service.sweep(req);

        assertThat(resp.discovered()).isEqualTo(3);
        assertThat(resp.deviceIds()).hasSize(3);
        assertThat(resp.perSourceCount().get(DiscoverySource.ARP)).isEqualTo(3);
    }

    @Test
    void sweep_pcapWithoutIface_throwsDiscoveryUnavailable() {
        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(null, 5, List.of(DiscoverySource.PCAP));
        assertThatThrownBy(() -> service.sweep(req))
            .isInstanceOf(DiscoveryUnavailableException.class)
            .hasMessageContaining("interface");
    }

    @Test
    void sweep_pcapNativeException_wrappedInDiscoveryUnavailable() throws Exception {
        when(pcapSniffer.sniff(anyString(), anyInt()))
            .thenThrow(new org.pcap4j.core.PcapNativeException("no pcap"));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.PCAP));
        assertThatThrownBy(() -> service.sweep(req))
            .isInstanceOf(DiscoveryUnavailableException.class);
    }

    @Test
    void sweep_lldpDisabledByDefault_skippedSilently() throws Exception {
        // Default lldpEnabled=false; requesting LLDP should not throw
        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(null, 5, List.of(DiscoverySource.LLDP));
        PassiveDiscoveryResponse resp = service.sweep(req);
        assertThat(resp.discovered()).isEqualTo(0);
    }

    @Test
    void sweep_emitsAuditEvent() throws Exception {
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.1.1", "bb:00:00:00:00:01", "0x1", "0x2", "eth0", null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.ARP));
        service.sweep(req);

        verify(auditService, times(1)).recordEvent(
            eq("discovery"),
            eq("PASSIVE_SWEEP"),
            eq("discovery"),
            anyString(),
            any()
        );
    }

    @Test
    void sweep_dedupesByMacWithIpFallback() throws Exception {
        // Two ARP rows for the same MAC at two different IPs (renumber event):
        //   MAC-primary dedupe collapses them to a single discovery.
        // Plus one MAC-less mDNS-style row — falls back to IP-key, kept as a separate entry.
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.2.1", "aa:00:00:00:00:01", "0x1", "0x2", "eth0", null),
            new DiscoveredNeighbor("10.0.2.99", "aa:00:00:00:00:01", "0x1", "0x2", "eth0", null),
            new DiscoveredNeighbor("10.0.2.50", null, null, null, null, null) // IP-only fallback
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.ARP));
        PassiveDiscoveryResponse resp = service.sweep(req);
        assertThat(resp.discovered()).isEqualTo(2);
    }

    @Test
    void sweep_pcapDisabledByFlag_skippedSilentlyEvenWhenRequested() throws Exception {
        // Build a service variant with pcapEnabled=false
        PassiveDiscoveryService disabled = new PassiveDiscoveryService(
            arpFactory, mdnsProbe, pcapSniffer, lldpDecoder, cdpDecoder,
            upsertService, auditService, recorder,
            false, false, false, clock);

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.PCAP));
        PassiveDiscoveryResponse resp = disabled.sweep(req);

        assertThat(resp.discovered()).isEqualTo(0);
        org.mockito.Mockito.verifyNoInteractions(pcapSniffer);
    }

    @Test
    void sweep_pcapEnabledByFlag_dispatchesAsBefore() throws Exception {
        when(pcapSniffer.sniff(anyString(), anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.4.1", "cc:00:00:00:00:01", null, null, "eth0", null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.PCAP));
        service.sweep(req);

        verify(pcapSniffer, times(1)).sniff(eq("eth0"), eq(5));
    }

    @Test
    void sweep_multiSource_aggregatesPerSourceCount() throws Exception {
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.3.1", "aa:00:00:00:00:01", "0x1", "0x2", "eth0", null),
            new DiscoveredNeighbor("10.0.3.2", "aa:00:00:00:00:02", "0x1", "0x2", "eth0", null)
        ));
        when(mdnsProbe.probe(anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.3.3", null, null, null, null, null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5,
            List.of(DiscoverySource.ARP, DiscoverySource.MDNS));
        PassiveDiscoveryResponse resp = service.sweep(req);

        assertThat(resp.perSourceCount().get(DiscoverySource.ARP)).isEqualTo(2);
        assertThat(resp.perSourceCount().get(DiscoverySource.MDNS)).isEqualTo(1);
    }

    @Test
    @SuppressWarnings("unchecked")
    void arpDiscoveryPropagatesIfaceIntoDevice() throws Exception {
        // Single ARP neighbor observed on iface "eth0" — assert the iface field is carried
        // through the toDiscovery orchestration into the upsertAll call.
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.5.1", "aa:bb:cc:dd:ee:ff", "0x1", "0x2", "eth0", null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.ARP));
        service.sweep(req);

        ArgumentCaptor<List<Discovery>> captor = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captor.capture());
        List<Discovery> captured = captor.getValue();
        assertThat(captured).hasSize(1);
        assertThat(captured.get(0).iface()).isEqualTo("eth0");
    }
}
