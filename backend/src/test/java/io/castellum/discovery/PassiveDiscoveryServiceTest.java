package io.castellum.discovery;

import io.castellum.audit.AuditLog;
import io.castellum.audit.AuditService;
import io.castellum.domain.DeviceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SpringBootTest
class PassiveDiscoveryServiceTest {

    @Autowired
    private PassiveDiscoveryService service;

    @Autowired
    private DeviceRepository deviceRepo;

    @MockBean
    private ArpCacheReader arpReader;

    @MockBean
    private MdnsProbe mdnsProbe;

    @MockBean
    private PcapSniffer pcapSniffer;

    @MockBean
    private LldpDecoder lldpDecoder;

    @MockBean
    private CdpDecoder cdpDecoder;

    @MockBean
    private AuditService auditService;

    @BeforeEach
    void setUp() {
        deviceRepo.deleteAll();
        when(auditService.recordEvent(any(), any(), any(), any(), any())).thenReturn(null);
    }

    @Test
    void sweep_arpOnly_callsUpsertPerNeighbor() {
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.0.1", "aa:00:00:00:00:01", "0x1", "0x2", "eth0"),
            new DiscoveredNeighbor("10.0.0.2", "aa:00:00:00:00:02", "0x1", "0x2", "eth0"),
            new DiscoveredNeighbor("10.0.0.3", "aa:00:00:00:00:03", "0x1", "0x2", "eth0")
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
    void sweep_lldpDisabledByDefault_skippedSilently() {
        // Default lldpEnabled=false; requesting LLDP_UNTESTED should not throw
        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(null, 5, List.of(DiscoverySource.LLDP_UNTESTED));
        PassiveDiscoveryResponse resp = service.sweep(req);
        assertThat(resp.discovered()).isEqualTo(0);
    }

    @Test
    void sweep_emitsAuditEvent() {
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.1.1", "bb:00:00:00:00:01", "0x1", "0x2", "eth0")
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
    void sweep_dedupesByIp() {
        // Two neighbors with the same IP — should produce 1 discovery
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.2.1", "aa:00:00:00:00:01", "0x1", "0x2", "eth0"),
            new DiscoveredNeighbor("10.0.2.1", "aa:00:00:00:00:02", "0x1", "0x2", "eth0")
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.ARP));
        PassiveDiscoveryResponse resp = service.sweep(req);
        assertThat(resp.discovered()).isEqualTo(1);
    }

    @Test
    void sweep_multiSource_aggregatesPerSourceCount() {
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.3.1", "aa:00:00:00:00:01", "0x1", "0x2", "eth0"),
            new DiscoveredNeighbor("10.0.3.2", "aa:00:00:00:00:02", "0x1", "0x2", "eth0")
        ));
        when(mdnsProbe.probe(anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.3.3", null, null, null, null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5,
            List.of(DiscoverySource.ARP, DiscoverySource.MDNS));
        PassiveDiscoveryResponse resp = service.sweep(req);

        assertThat(resp.perSourceCount().get(DiscoverySource.ARP)).isEqualTo(2);
        assertThat(resp.perSourceCount().get(DiscoverySource.MDNS)).isEqualTo(1);
    }
}
