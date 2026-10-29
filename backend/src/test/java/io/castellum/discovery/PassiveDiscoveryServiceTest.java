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
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
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
    @Mock private LldpCapture lldpCapture;
    @Mock private CdpCapture cdpCapture;
    @Mock private DhcpCapture dhcpCapture;
    @Mock private ConnTableReader connTableReader;
    @Mock private GatewayProbe gatewayProbe;
    @Mock private DeviceUpsertService upsertService;
    @Mock private AuditService auditService;
    @Mock private DiscoverySweepRecorder recorder;

    private PassiveDiscoveryService service;
    private Clock clock;

    @BeforeEach
    void setUp() {
        clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        service = new PassiveDiscoveryService(
            arpFactory, mdnsProbe, pcapSniffer, lldpCapture, cdpCapture, dhcpCapture,
            connTableReader, gatewayProbe,
            upsertService, auditService, recorder,
            false /* lldpEnabled */,
            false /* cdpEnabled */,
            false /* dhcpEnabled */,
            true /* pcapEnabled — existing PCAP cases assume enabled */,
            true /* connTableEnabled */,
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
            new DiscoveredNeighbor("10.0.0.1", "aa:00:00:00:00:01", "0x1", "0x2", "eth0", null, null),
            new DiscoveredNeighbor("10.0.0.2", "aa:00:00:00:00:02", "0x1", "0x2", "eth0", null, null),
            new DiscoveredNeighbor("10.0.0.3", "aa:00:00:00:00:03", "0x1", "0x2", "eth0", null, null)
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
            new DiscoveredNeighbor("10.0.1.1", "bb:00:00:00:00:01", "0x1", "0x2", "eth0", null, null)
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
            new DiscoveredNeighbor("10.0.2.1", "aa:00:00:00:00:01", "0x1", "0x2", "eth0", null, null),
            new DiscoveredNeighbor("10.0.2.99", "aa:00:00:00:00:01", "0x1", "0x2", "eth0", null, null),
            new DiscoveredNeighbor("10.0.2.50", null, null, null, null, null, null) // IP-only fallback
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.ARP));
        PassiveDiscoveryResponse resp = service.sweep(req);
        assertThat(resp.discovered()).isEqualTo(2);
    }

    /**
     * Cross-source reconcile: the gateway is virtually always present in the ARP cache, so
     * ARP yields (mac, gw-ip) while GATEWAY yields (null, gw-ip) for the SAME IP. The
     * null-MAC row must be dropped before the batch reaches upsertAll — two rows for one
     * (ip, origin) would both INSERT on an empty DB and violate device_ip_origin_unique,
     * failing the whole sweep. The discovered count and recorder total must reflect the
     * reconciled batch, not the sum of the two dedupe maps.
     */
    @Test
    @SuppressWarnings("unchecked")
    void sweep_arpAndGatewaySameIp_dropsNullMacRow_singleBatchEntry() throws Exception {
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.9.1", "aa:bb:cc:dd:ee:01", "0x1", "0x2", "eth0", null, null)
        ));
        when(gatewayProbe.probe()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.9.1", null, null, null, "eth0", null, null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(null, 5,
            List.of(DiscoverySource.ARP, DiscoverySource.GATEWAY));
        PassiveDiscoveryResponse resp = service.sweep(req);

        ArgumentCaptor<List<Discovery>> captor = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captor.capture());
        List<Discovery> batch = captor.getValue();
        assertThat(batch).hasSize(1);
        assertThat(batch.get(0).ipAddress()).isEqualTo("10.0.9.1");
        assertThat(batch.get(0).macAddress()).isEqualTo("aa:bb:cc:dd:ee:01"); // MAC row survives

        // Per-source counts still report raw observations; the dedupe applies to the batch only.
        assertThat(resp.perSourceCount().get(DiscoverySource.ARP)).isEqualTo(1);
        assertThat(resp.perSourceCount().get(DiscoverySource.GATEWAY)).isEqualTo(1);
        assertThat(resp.discovered()).isEqualTo(1);
        verify(recorder).finish(eq(42L), eq("OK"), eq(1), eq(1), any(), eq("eth0"));
    }

    /**
     * Reconcile must not lose information from the dropped null-MAC row: an mDNS hostname
     * observed for an IP that ARP also saw (with a MAC, no hostname) backfills the surviving
     * MAC-bearing discovery (fill-when-null).
     */
    @Test
    @SuppressWarnings("unchecked")
    void sweep_arpAndMdnsSameIp_survivingMacRowCarriesMdnsHostname() throws Exception {
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.9.2", "aa:bb:cc:dd:ee:02", "0x1", "0x2", "eth0", null, null)
        ));
        when(mdnsProbe.probe(anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.9.2", null, null, null, null, "printer.local", null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5,
            List.of(DiscoverySource.ARP, DiscoverySource.MDNS));
        PassiveDiscoveryResponse resp = service.sweep(req);

        ArgumentCaptor<List<Discovery>> captor = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captor.capture());
        List<Discovery> batch = captor.getValue();
        assertThat(batch).hasSize(1);
        assertThat(batch.get(0).macAddress()).isEqualTo("aa:bb:cc:dd:ee:02");
        assertThat(batch.get(0).hostname()).isEqualTo("printer.local");
        assertThat(resp.discovered()).isEqualTo(1);
    }

    /**
     * reconcileMacPrimacy iface backfill: when the MAC-bearing row carries null iface
     * and the dropped null-MAC row carries a real iface, the surviving MAC row must be
     * updated with the dropped row's iface (fill-when-null, mirrors hostname semantics).
     *
     * <p>Scenario: GATEWAY probe finds the router by IP only (null-MAC, iface="eth0"),
     * while ARP also sees the same IP but the ARP entry carries no iface (null). After
     * reconcile the ARP (MAC-bearing) row must carry "eth0" — so the upsertAll call
     * receives a Discovery with both the MAC and the iface set.
     */
    @Test
    @SuppressWarnings("unchecked")
    void sweep_arpAndGatewaySameIp_ifaceBackfilledFromDroppedRow() throws Exception {
        // ARP row: has MAC, but null iface
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.9.5", "aa:bb:cc:dd:ee:05", "0x1", "0x2", null, null, null)
        ));
        // GATEWAY row: null-MAC, iface="eth0"
        when(gatewayProbe.probe()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.9.5", null, null, null, "eth0", null, null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(null, 5,
            List.of(DiscoverySource.ARP, DiscoverySource.GATEWAY));
        service.sweep(req);

        ArgumentCaptor<List<Discovery>> captor = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captor.capture());
        List<Discovery> batch = captor.getValue();

        // The null-MAC GATEWAY row must be dropped — only the ARP MAC row survives
        assertThat(batch).hasSize(1);
        assertThat(batch.get(0).macAddress())
            .as("surviving row must be the ARP (MAC-bearing) row")
            .isEqualTo("aa:bb:cc:dd:ee:05");
        assertThat(batch.get(0).iface())
            .as("iface from the dropped GATEWAY row must backfill the surviving ARP row")
            .isEqualTo("eth0");
    }

    @Test
    void sweep_pcapDisabledByFlag_skippedSilentlyEvenWhenRequested() throws Exception {
        // Build a service variant with pcapEnabled=false
        PassiveDiscoveryService disabled = new PassiveDiscoveryService(
            arpFactory, mdnsProbe, pcapSniffer, lldpCapture, cdpCapture, dhcpCapture,
            connTableReader, gatewayProbe,
            upsertService, auditService, recorder,
            false, false, false, false, true, clock);

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.PCAP));
        PassiveDiscoveryResponse resp = disabled.sweep(req);

        assertThat(resp.discovered()).isEqualTo(0);
        org.mockito.Mockito.verifyNoInteractions(pcapSniffer);
    }

    @Test
    void sweep_connTableDisabledByFlag_skippedSilentlyEvenWhenRequested() throws Exception {
        // Build a service variant with connTableEnabled=false
        PassiveDiscoveryService disabled = new PassiveDiscoveryService(
            arpFactory, mdnsProbe, pcapSniffer, lldpCapture, cdpCapture, dhcpCapture,
            connTableReader, gatewayProbe,
            upsertService, auditService, recorder,
            false, false, false, true, false, clock);

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(null, 5, List.of(DiscoverySource.CONN_TABLE));
        PassiveDiscoveryResponse resp = disabled.sweep(req);

        assertThat(resp.discovered()).isEqualTo(0);
        org.mockito.Mockito.verifyNoInteractions(connTableReader);
    }

    @Test
    void sweep_connTableEnabled_collectsRemoteEndpoints() throws Exception {
        when(connTableReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("8.8.8.8", null, null, null, null, null, null),
            new DiscoveredNeighbor("140.82.121.4", null, null, null, null, null, null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(null, 5, List.of(DiscoverySource.CONN_TABLE));
        PassiveDiscoveryResponse resp = service.sweep(req);

        assertThat(resp.discovered()).isEqualTo(2);
        assertThat(resp.perSourceCount().get(DiscoverySource.CONN_TABLE)).isEqualTo(2);
    }

    @Test
    void sweep_gatewaySource_dispatchesProbe() throws Exception {
        when(gatewayProbe.probe()).thenReturn(List.of(
            new DiscoveredNeighbor("192.168.1.1", null, null, null, "eth0", null, null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(null, 5, List.of(DiscoverySource.GATEWAY));
        PassiveDiscoveryResponse resp = service.sweep(req);

        assertThat(resp.discovered()).isEqualTo(1);
        assertThat(resp.perSourceCount().get(DiscoverySource.GATEWAY)).isEqualTo(1);
        verify(gatewayProbe, times(1)).probe();
    }

    @Test
    void sweep_pcapEnabledByFlag_dispatchesAsBefore() throws Exception {
        when(pcapSniffer.sniff(anyString(), anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.4.1", "cc:00:00:00:00:01", null, null, "eth0", null, null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.PCAP));
        service.sweep(req);

        verify(pcapSniffer, times(1)).sniff(eq("eth0"), eq(5));
    }

    @Test
    void sweep_multiSource_aggregatesPerSourceCount() throws Exception {
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.3.1", "aa:00:00:00:00:01", "0x1", "0x2", "eth0", null, null),
            new DiscoveredNeighbor("10.0.3.2", "aa:00:00:00:00:02", "0x1", "0x2", "eth0", null, null)
        ));
        when(mdnsProbe.probe(anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.3.3", null, null, null, null, null, null)
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
            new DiscoveredNeighbor("10.0.5.1", "aa:bb:cc:dd:ee:ff", "0x1", "0x2", "eth0", null, null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.ARP));
        service.sweep(req);

        ArgumentCaptor<List<Discovery>> captor = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captor.capture());
        List<Discovery> captured = captor.getValue();
        assertThat(captured).hasSize(1);
        assertThat(captured.get(0).iface()).isEqualTo("eth0");
    }

    /**
     * AC3 — success path: recorder.finish receives the real neighbor_count (not 0) and the
     * observed iface derived from the collected neighbors' iface field.
     */
    @Test
    void sweep_arpSuccess_recordsRealNeighborCountAndObservedIface() throws Exception {
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.0.1", "aa:00:00:00:00:01", "0x1", "0x2", "eth0", null, null),
            new DiscoveredNeighbor("10.0.0.2", "aa:00:00:00:00:02", "0x1", "0x2", "eth0", null, null),
            new DiscoveredNeighbor("10.0.0.3", "aa:00:00:00:00:03", "0x1", "0x2", "eth0", null, null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.ARP));
        service.sweep(req);

        // finish must receive real neighbor_count=3 and observed iface="eth0"
        verify(recorder).finish(eq(42L), eq("OK"), eq(3), eq(3), any(), eq("eth0"));
    }

    /**
     * AC3 — scheduled path: even though scheduledSweep() builds the request with a null iface,
     * the finish call must carry the observed iface derived from the ARP neighbors.
     * Pure Mockito — no real scheduler is invoked, no host interface is touched.
     */
    @Test
    void scheduledSweep_recordsObservedIfaceEvenWhenRequestIfaceNull() throws Exception {
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.8.1", "dd:00:00:00:00:01", "0x1", "0x2", "eth0", null, null)
        ));

        service.scheduledSweep();

        // The request has iface=null, but the collected neighbor carries "eth0"
        verify(recorder).finish(eq(42L), eq("OK"), eq(1), eq(1), any(), eq("eth0"));
    }

    /**
     * Scheduled sweeps now fan out the three local-read sources (ARP, CONN_TABLE,
     * GATEWAY) — not ARP alone — so off-network peers and the router appear in the
     * inventory without a manual sweep.
     */
    @Test
    void scheduledSweep_requestsArpConnTableAndGatewaySources() throws Exception {
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.8.1", "dd:00:00:00:00:01", "0x1", "0x2", "eth0", null, null)
        ));
        when(connTableReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("8.8.8.8", null, null, null, null, null, null)
        ));
        when(gatewayProbe.probe()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.8.254", null, null, null, "eth0", null, null)
        ));

        PassiveDiscoveryResponse resp = service.scheduledSweep();

        verify(recorder).start(eq("ARP,CONN_TABLE,GATEWAY"), isNull(), eq("SCHEDULER"));
        verify(connTableReader, times(1)).read();
        verify(gatewayProbe, times(1)).probe();
        assertThat(resp.perSourceCount().get(DiscoverySource.ARP)).isEqualTo(1);
        assertThat(resp.perSourceCount().get(DiscoverySource.CONN_TABLE)).isEqualTo(1);
        assertThat(resp.perSourceCount().get(DiscoverySource.GATEWAY)).isEqualTo(1);
        assertThat(resp.discovered()).isEqualTo(3);
    }

    /**
     * AC4 — FAILED path: when upsertAll throws a RuntimeException, the sweep must be recorded
     * as FAILED and the exception re-thrown. (The log.error with stack trace is not asserted
     * here — AC4 only requires it be logged; assert the FAILED-record + rethrow contract.)
     */
    @Test
    void sweep_runtimeFailure_recordsFailedAndRethrows() throws Exception {
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.9.1", "ee:00:00:00:00:01", "0x1", "0x2", "eth0", null, null)
        ));
        // upsertAll throws after successful neighbor collection → hits catch (RuntimeException)
        when(upsertService.upsertAll(anyList())).thenThrow(new RuntimeException("DB constraint"));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.ARP));

        assertThatThrownBy(() -> service.sweep(req))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("DB constraint");

        verify(recorder).finish(eq(42L), eq("FAILED"), eq(0), eq(0), isNull(), any());
    }

    // ────────────────────────────────────────────────────────────────────────
    // Slice 5 — LLDP capture dispatch + MAC-only neighbor persistence
    // ────────────────────────────────────────────────────────────────────────

    /** Service variant with the LLDP feature flag enabled (mirrors the disabled-flag variants above). */
    private PassiveDiscoveryService lldpEnabledService() {
        return new PassiveDiscoveryService(
            arpFactory, mdnsProbe, pcapSniffer, lldpCapture, cdpCapture, dhcpCapture,
            connTableReader, gatewayProbe,
            upsertService, auditService, recorder,
            true /* lldpEnabled */, false, false, true, true, clock);
    }

    /**
     * LLDP enabled + iface given: the sweep must dispatch {@code lldpCapture.capture(iface,
     * duration)} (NOT the bare decoder stub) and flow the captured neighbors into upsertAll.
     */
    @Test
    @SuppressWarnings("unchecked")
    void sweep_lldpEnabledWithIface_dispatchesCaptureAndUpsertsNeighbors() throws Exception {
        PassiveDiscoveryService lldpService = lldpEnabledService();
        when(lldpCapture.capture(anyString(), anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor("192.168.1.10", "aa:bb:cc:dd:ee:0e", null, null, "eth0", "switch01", null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.LLDP));
        PassiveDiscoveryResponse resp = lldpService.sweep(req);

        verify(lldpCapture, times(1)).capture(eq("eth0"), eq(5));
        ArgumentCaptor<List<Discovery>> captor = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captor.capture());
        List<Discovery> batch = captor.getValue();
        assertThat(batch).hasSize(1);
        assertThat(batch.get(0).ipAddress()).isEqualTo("192.168.1.10");
        assertThat(batch.get(0).macAddress()).isEqualTo("aa:bb:cc:dd:ee:0e");
        assertThat(batch.get(0).hostname()).isEqualTo("switch01");
        assertThat(resp.perSourceCount().get(DiscoverySource.LLDP)).isEqualTo(1);
        assertThat(resp.discovered()).isEqualTo(1);
    }

    /**
     * Intake validation (mirrors the PCAP block): LLDP enabled + LLDP requested + null/blank
     * iface must throw BEFORE recorder.start — invalid input produces no discovery_sweep row.
     */
    @Test
    void sweep_lldpEnabledRequestedWithBlankIface_throwsBeforeSweepRowOpened() {
        PassiveDiscoveryService lldpService = lldpEnabledService();

        PassiveDiscoveryRequest nullIface = new PassiveDiscoveryRequest(null, 5, List.of(DiscoverySource.LLDP));
        assertThatThrownBy(() -> lldpService.sweep(nullIface))
            .isInstanceOf(DiscoveryUnavailableException.class)
            .hasMessageContaining("interface");

        PassiveDiscoveryRequest blankIface = new PassiveDiscoveryRequest("   ", 5, List.of(DiscoverySource.LLDP));
        assertThatThrownBy(() -> lldpService.sweep(blankIface))
            .isInstanceOf(DiscoveryUnavailableException.class)
            .hasMessageContaining("interface");

        verify(recorder, never()).start(anyString(), any(), anyString());
    }

    /**
     * Disabled-flag soft-skip stays: LLDP requested with lldpEnabled=false must complete the
     * sweep without ever touching the capture collaborator (regression guard over the rewrite
     * of the LLDP dispatch case).
     */
    @Test
    void sweep_lldpDisabledByFlag_captureNeverInvoked() throws Exception {
        // Default service variant has lldpEnabled=false
        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.LLDP));
        PassiveDiscoveryResponse resp = service.sweep(req);

        assertThat(resp.discovered()).isEqualTo(0);
        org.mockito.Mockito.verifyNoInteractions(lldpCapture);
    }

    /**
     * Drop-site relaxation: a MAC-only neighbor (ip null, mac set) must NOT be dropped —
     * it reaches upsertAll keyed by the deterministic placeholder IP. The literal
     * {@code "mac:aa-bb-cc-dd-ee-ff"} (lowercase, colons → dashes) pins the convention itself.
     */
    @Test
    @SuppressWarnings("unchecked")
    void sweep_lldpMacOnlyNeighbor_upsertedWithPlaceholderIp() throws Exception {
        PassiveDiscoveryService lldpService = lldpEnabledService();
        when(lldpCapture.capture(anyString(), anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor(null, "aa:bb:cc:dd:ee:ff", null, null, "eth0", null, null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.LLDP));
        PassiveDiscoveryResponse resp = lldpService.sweep(req);

        ArgumentCaptor<List<Discovery>> captor = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captor.capture());
        List<Discovery> batch = captor.getValue();
        assertThat(batch).hasSize(1);
        assertThat(batch.get(0).ipAddress())
            .as("MAC-only neighbor must be keyed by the synthetic placeholder IP")
            .isEqualTo("mac:aa-bb-cc-dd-ee-ff");
        assertThat(batch.get(0).macAddress()).isEqualTo("aa:bb:cc:dd:ee:ff");
        assertThat(resp.perSourceCount().get(DiscoverySource.LLDP)).isEqualTo(1);
        assertThat(resp.discovered()).isEqualTo(1);
    }

    /**
     * Drop only when BOTH ipAddress and macAddress are null/blank: a hostname-only neighbor
     * is still dropped (cannot key the upsert) but counts toward perSourceCount as a real
     * observation.
     */
    @Test
    void sweep_lldpNeighborWithNullIpAndNullMac_droppedButCounted() throws Exception {
        PassiveDiscoveryService lldpService = lldpEnabledService();
        when(lldpCapture.capture(anyString(), anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor(null, null, null, null, "eth0", "ghost-switch", null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.LLDP));
        PassiveDiscoveryResponse resp = lldpService.sweep(req);

        assertThat(resp.discovered()).isEqualTo(0);
        assertThat(resp.perSourceCount().get(DiscoverySource.LLDP)).isEqualTo(1);
        verify(upsertService, never()).upsertAll(anyList());
    }

    /**
     * Same sweep, same MAC: ARP supplies the real IP, LLDP supplies a MAC-only row with a
     * sysname. ARP collected first — the later placeholder row must NOT overwrite the real-IP
     * row, but its hostname must backfill onto it (fill-when-null, mirroring
     * reconcileMacPrimacy). Exactly one Discovery reaches upsertAll: real IP + LLDP hostname.
     */
    @Test
    @SuppressWarnings("unchecked")
    void sweep_arpRealIpThenLldpMacOnly_singleRowRealIpWithLldpHostname() throws Exception {
        PassiveDiscoveryService lldpService = lldpEnabledService();
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.0.5", "aa:bb:cc:dd:ee:ff", "0x1", "0x2", "eth0", null, null)
        ));
        when(lldpCapture.capture(anyString(), anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor(null, "aa:bb:cc:dd:ee:ff", null, null, "eth0", "switch01", null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(
            "eth0", 5, List.of(DiscoverySource.ARP, DiscoverySource.LLDP));
        lldpService.sweep(req);

        ArgumentCaptor<List<Discovery>> captor = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captor.capture());
        List<Discovery> batch = captor.getValue();
        assertThat(batch).hasSize(1);
        assertThat(batch.get(0).ipAddress())
            .as("real ARP IP must survive a later MAC-only placeholder row")
            .isEqualTo("10.0.0.5");
        assertThat(batch.get(0).hostname())
            .as("LLDP sysname must backfill onto the surviving real-IP row")
            .isEqualTo("switch01");
        assertThat(batch.get(0).macAddress()).isEqualTo("aa:bb:cc:dd:ee:ff");
    }

    /**
     * Same collision, reverse collection order: LLDP's MAC-only placeholder row lands first,
     * then ARP's real-IP row arrives. The real IP must replace the placeholder while the LLDP
     * hostname still backfills. Order-independence is the point — same single-row outcome.
     */
    @Test
    @SuppressWarnings("unchecked")
    void sweep_lldpMacOnlyThenArpRealIp_singleRowRealIpWithLldpHostname() throws Exception {
        PassiveDiscoveryService lldpService = lldpEnabledService();
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.0.5", "aa:bb:cc:dd:ee:ff", "0x1", "0x2", "eth0", null, null)
        ));
        when(lldpCapture.capture(anyString(), anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor(null, "aa:bb:cc:dd:ee:ff", null, null, "eth0", "switch01", null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(
            "eth0", 5, List.of(DiscoverySource.LLDP, DiscoverySource.ARP));
        lldpService.sweep(req);

        ArgumentCaptor<List<Discovery>> captor = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captor.capture());
        List<Discovery> batch = captor.getValue();
        assertThat(batch).hasSize(1);
        assertThat(batch.get(0).ipAddress())
            .as("real ARP IP must replace an earlier MAC-only placeholder row")
            .isEqualTo("10.0.0.5");
        assertThat(batch.get(0).hostname())
            .as("LLDP sysname must backfill onto the surviving real-IP row")
            .isEqualTo("switch01");
        assertThat(batch.get(0).macAddress()).isEqualTo("aa:bb:cc:dd:ee:ff");
    }

    // ────────────────────────────────────────────────────────────────────────
    // Slice 6 — CDP capture dispatch + MAC-only neighbor persistence
    // ────────────────────────────────────────────────────────────────────────

    /** Service variant with the CDP feature flag enabled (mirrors lldpEnabledService above). */
    private PassiveDiscoveryService cdpEnabledService() {
        return new PassiveDiscoveryService(
            arpFactory, mdnsProbe, pcapSniffer, lldpCapture, cdpCapture, dhcpCapture,
            connTableReader, gatewayProbe,
            upsertService, auditService, recorder,
            false /* lldpEnabled */, true /* cdpEnabled */, false /* dhcpEnabled */, true, true, clock);
    }

    /**
     * CDP enabled + iface given: the sweep must dispatch {@code cdpCapture.capture(iface,
     * duration)} (NOT the old decoder stub) and flow the captured neighbors into upsertAll.
     */
    @Test
    @SuppressWarnings("unchecked")
    void sweep_cdpEnabledWithIface_dispatchesCaptureAndUpsertsNeighbors() throws Exception {
        PassiveDiscoveryService cdpService = cdpEnabledService();
        when(cdpCapture.capture(anyString(), anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor("192.168.1.20", "00:1b:54:ab:cd:ef", null, null, "eth0", "switch-cdp-01", null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.CDP));
        PassiveDiscoveryResponse resp = cdpService.sweep(req);

        verify(cdpCapture, times(1)).capture(eq("eth0"), eq(5));
        ArgumentCaptor<List<Discovery>> captor = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captor.capture());
        List<Discovery> batch = captor.getValue();
        assertThat(batch).hasSize(1);
        assertThat(batch.get(0).ipAddress()).isEqualTo("192.168.1.20");
        assertThat(batch.get(0).macAddress()).isEqualTo("00:1b:54:ab:cd:ef");
        assertThat(batch.get(0).hostname()).isEqualTo("switch-cdp-01");
        assertThat(resp.perSourceCount().get(DiscoverySource.CDP)).isEqualTo(1);
        assertThat(resp.discovered()).isEqualTo(1);
    }

    /**
     * Intake validation (mirrors the PCAP/LLDP blocks): CDP enabled + CDP requested +
     * null/blank iface must throw BEFORE recorder.start — invalid input produces no
     * discovery_sweep row.
     */
    @Test
    void sweep_cdpEnabledRequestedWithBlankIface_throwsBeforeSweepRowOpened() {
        PassiveDiscoveryService cdpService = cdpEnabledService();

        PassiveDiscoveryRequest nullIface = new PassiveDiscoveryRequest(null, 5, List.of(DiscoverySource.CDP));
        assertThatThrownBy(() -> cdpService.sweep(nullIface))
            .isInstanceOf(DiscoveryUnavailableException.class)
            .hasMessageContaining("interface");

        PassiveDiscoveryRequest blankIface = new PassiveDiscoveryRequest("   ", 5, List.of(DiscoverySource.CDP));
        assertThatThrownBy(() -> cdpService.sweep(blankIface))
            .isInstanceOf(DiscoveryUnavailableException.class)
            .hasMessageContaining("interface");

        verify(recorder, never()).start(anyString(), any(), anyString());
    }

    /**
     * Disabled-flag soft-skip stays: CDP requested with cdpEnabled=false must complete the
     * sweep without ever touching the capture collaborator (regression guard over the rewrite
     * of the CDP dispatch case).
     */
    @Test
    void sweep_cdpDisabledByFlag_captureNeverInvoked() throws Exception {
        // Default service variant has cdpEnabled=false
        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.CDP));
        PassiveDiscoveryResponse resp = service.sweep(req);

        assertThat(resp.discovered()).isEqualTo(0);
        org.mockito.Mockito.verifyNoInteractions(cdpCapture);
    }

    /**
     * Drop-site relaxation for CDP: a MAC-only neighbor (ip null, mac set) must NOT be
     * dropped — it reaches upsertAll keyed by the deterministic placeholder IP. The literal
     * {@code "mac:aa-bb-cc-dd-ee-ff"} (lowercase, colons → dashes) pins the convention itself.
     */
    @Test
    @SuppressWarnings("unchecked")
    void sweep_cdpMacOnlyNeighbor_upsertedWithPlaceholderIp() throws Exception {
        PassiveDiscoveryService cdpService = cdpEnabledService();
        when(cdpCapture.capture(anyString(), anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor(null, "aa:bb:cc:dd:ee:ff", null, null, "eth0", null, null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.CDP));
        PassiveDiscoveryResponse resp = cdpService.sweep(req);

        ArgumentCaptor<List<Discovery>> captor = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captor.capture());
        List<Discovery> batch = captor.getValue();
        assertThat(batch).hasSize(1);
        assertThat(batch.get(0).ipAddress())
            .as("MAC-only neighbor must be keyed by the synthetic placeholder IP")
            .isEqualTo("mac:aa-bb-cc-dd-ee-ff");
        assertThat(batch.get(0).macAddress()).isEqualTo("aa:bb:cc:dd:ee:ff");
        assertThat(resp.perSourceCount().get(DiscoverySource.CDP)).isEqualTo(1);
        assertThat(resp.discovered()).isEqualTo(1);
    }

    /**
     * Capability failure: a PcapNativeException from the capture must surface as a
     * DiscoveryUnavailableException carrying the CDP-specific message, and the sweep row
     * must finish UNAVAILABLE (mirrors the PCAP/LLDP wrap contract).
     */
    @Test
    void sweep_cdpPcapNativeException_wrappedInDiscoveryUnavailableAndRowUnavailable() throws Exception {
        PassiveDiscoveryService cdpService = cdpEnabledService();
        when(cdpCapture.capture(anyString(), anyInt()))
            .thenThrow(new org.pcap4j.core.PcapNativeException("no pcap"));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.CDP));
        assertThatThrownBy(() -> cdpService.sweep(req))
            .isInstanceOf(DiscoveryUnavailableException.class)
            .hasMessageContaining("CDP capture failed on interface 'eth0'");

        verify(recorder).finish(eq(42L), eq("UNAVAILABLE"), eq(0), eq(0), isNull(), any());
    }

    /**
     * Same sweep, same MAC: ARP supplies the real IP, CDP supplies a MAC-only row with a
     * Device-ID hostname. ARP collected first — the later placeholder row must NOT overwrite
     * the real-IP row, but its hostname must backfill onto it (pins mergeOnMac for the CDP
     * source). Exactly one Discovery reaches upsertAll: real IP + CDP hostname.
     */
    @Test
    @SuppressWarnings("unchecked")
    void sweep_arpRealIpThenCdpMacOnly_singleRowRealIpWithCdpHostname() throws Exception {
        PassiveDiscoveryService cdpService = cdpEnabledService();
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.0.7", "00:1b:54:ab:cd:ef", "0x1", "0x2", "eth0", null, null)
        ));
        when(cdpCapture.capture(anyString(), anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor(null, "00:1b:54:ab:cd:ef", null, null, "eth0", "switch-cdp-01", null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(
            "eth0", 5, List.of(DiscoverySource.ARP, DiscoverySource.CDP));
        cdpService.sweep(req);

        ArgumentCaptor<List<Discovery>> captor = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captor.capture());
        List<Discovery> batch = captor.getValue();
        assertThat(batch).hasSize(1);
        assertThat(batch.get(0).ipAddress())
            .as("real ARP IP must survive a later MAC-only placeholder row")
            .isEqualTo("10.0.0.7");
        assertThat(batch.get(0).hostname())
            .as("CDP Device-ID must backfill onto the surviving real-IP row")
            .isEqualTo("switch-cdp-01");
        assertThat(batch.get(0).macAddress()).isEqualTo("00:1b:54:ab:cd:ef");
    }

    /**
     * Same collision, reverse collection order: CDP's MAC-only placeholder row lands first,
     * then ARP's real-IP row arrives. The real IP must replace the placeholder while the CDP
     * hostname still backfills. Order-independence is the point — same single-row outcome.
     */
    @Test
    @SuppressWarnings("unchecked")
    void sweep_cdpMacOnlyThenArpRealIp_singleRowRealIpWithCdpHostname() throws Exception {
        PassiveDiscoveryService cdpService = cdpEnabledService();
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.0.7", "00:1b:54:ab:cd:ef", "0x1", "0x2", "eth0", null, null)
        ));
        when(cdpCapture.capture(anyString(), anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor(null, "00:1b:54:ab:cd:ef", null, null, "eth0", "switch-cdp-01", null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(
            "eth0", 5, List.of(DiscoverySource.CDP, DiscoverySource.ARP));
        cdpService.sweep(req);

        ArgumentCaptor<List<Discovery>> captor = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captor.capture());
        List<Discovery> batch = captor.getValue();
        assertThat(batch).hasSize(1);
        assertThat(batch.get(0).ipAddress())
            .as("real ARP IP must replace an earlier MAC-only placeholder row")
            .isEqualTo("10.0.0.7");
        assertThat(batch.get(0).hostname())
            .as("CDP Device-ID must backfill onto the surviving real-IP row")
            .isEqualTo("switch-cdp-01");
        assertThat(batch.get(0).macAddress()).isEqualTo("00:1b:54:ab:cd:ef");
    }

    // ────────────────────────────────────────────────────────────────────────
    // DHCP capture dispatch + role-hint thread-through
    // ────────────────────────────────────────────────────────────────────────

    /** Service variant with the DHCP feature flag enabled (mirrors cdpEnabledService above). */
    private PassiveDiscoveryService dhcpEnabledService() {
        return new PassiveDiscoveryService(
            arpFactory, mdnsProbe, pcapSniffer, lldpCapture, cdpCapture, dhcpCapture,
            connTableReader, gatewayProbe,
            upsertService, auditService, recorder,
            false /* lldpEnabled */, false /* cdpEnabled */, true /* dhcpEnabled */, true, true, clock);
    }

    /** Service variant with LLDP AND DHCP enabled (for the cross-source mergeOnMac pins). */
    private PassiveDiscoveryService lldpAndDhcpEnabledService() {
        return new PassiveDiscoveryService(
            arpFactory, mdnsProbe, pcapSniffer, lldpCapture, cdpCapture, dhcpCapture,
            connTableReader, gatewayProbe,
            upsertService, auditService, recorder,
            true /* lldpEnabled */, false /* cdpEnabled */, true /* dhcpEnabled */, true, true, clock);
    }

    /**
     * S1 + S9. DHCP enabled + iface given: the sweep must dispatch
     * {@code dhcpCapture.capture(iface, duration)} and flow the captured neighbors into
     * upsertAll — with {@code toDiscovery} passing each neighbor's roleHint through
     * (the GATEWAY hint must arrive on the Discovery row, not be dropped to null).
     */
    @Test
    @SuppressWarnings("unchecked")
    void sweep_dhcpEnabledWithIface_dispatchesCaptureAndPassesRoleHintThrough() throws Exception {
        PassiveDiscoveryService dhcpService = dhcpEnabledService();
        when(dhcpCapture.capture(anyString(), anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor("192.168.1.50", "52:54:00:12:34:56", null, null, "eth0", "laptop-7", null),
            new DiscoveredNeighbor("192.168.1.1", null, null, null, "eth0", null, RoleHint.GATEWAY)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.DHCP));
        PassiveDiscoveryResponse resp = dhcpService.sweep(req);

        verify(dhcpCapture, times(1)).capture(eq("eth0"), eq(5));
        ArgumentCaptor<List<Discovery>> captor = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captor.capture());
        List<Discovery> batch = captor.getValue();
        assertThat(batch).hasSize(2);

        Discovery client = batch.stream().filter(d -> d.ipAddress().equals("192.168.1.50")).findFirst().orElseThrow();
        assertThat(client.macAddress()).isEqualTo("52:54:00:12:34:56");
        assertThat(client.hostname()).isEqualTo("laptop-7");
        assertThat(client.roleHint()).isNull();

        Discovery gateway = batch.stream().filter(d -> d.ipAddress().equals("192.168.1.1")).findFirst().orElseThrow();
        assertThat(gateway.roleHint())
            .as("toDiscovery must pass the neighbor's roleHint through to the Discovery row")
            .isEqualTo(RoleHint.GATEWAY);
        assertThat(gateway.source()).isEqualTo(DiscoverySource.DHCP);

        assertThat(resp.perSourceCount().get(DiscoverySource.DHCP)).isEqualTo(2);
        assertThat(resp.discovered()).isEqualTo(2);
    }

    /**
     * S2. Intake validation (mirrors the PCAP/LLDP/CDP blocks): DHCP enabled + DHCP
     * requested + null/blank iface must throw BEFORE recorder.start — invalid input
     * produces no discovery_sweep row.
     */
    @Test
    void sweep_dhcpEnabledRequestedWithBlankIface_throwsBeforeSweepRowOpened() {
        PassiveDiscoveryService dhcpService = dhcpEnabledService();

        PassiveDiscoveryRequest nullIface = new PassiveDiscoveryRequest(null, 5, List.of(DiscoverySource.DHCP));
        assertThatThrownBy(() -> dhcpService.sweep(nullIface))
            .isInstanceOf(DiscoveryUnavailableException.class)
            .hasMessageContaining("DHCP source requires interface name");

        PassiveDiscoveryRequest blankIface = new PassiveDiscoveryRequest("   ", 5, List.of(DiscoverySource.DHCP));
        assertThatThrownBy(() -> dhcpService.sweep(blankIface))
            .isInstanceOf(DiscoveryUnavailableException.class)
            .hasMessageContaining("DHCP source requires interface name");

        verify(recorder, never()).start(anyString(), any(), anyString());
    }

    /**
     * S3. Disabled-flag soft-skip: DHCP requested with dhcpEnabled=false must complete
     * the sweep without ever touching the capture collaborator.
     */
    @Test
    void sweep_dhcpDisabledByFlag_captureNeverInvoked() throws Exception {
        // Default service variant has dhcpEnabled=false
        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.DHCP));
        PassiveDiscoveryResponse resp = service.sweep(req);

        assertThat(resp.discovered()).isEqualTo(0);
        org.mockito.Mockito.verifyNoInteractions(dhcpCapture);
    }

    /**
     * S4. Drop-site relaxation for DHCP: a DISCOVER client (MAC, no IP) must NOT be
     * dropped — it reaches upsertAll keyed by the deterministic placeholder IP. The
     * literal {@code "mac:52-54-00-12-34-56"} pins the convention itself.
     */
    @Test
    @SuppressWarnings("unchecked")
    void sweep_dhcpMacOnlyClient_upsertedWithPlaceholderIp() throws Exception {
        PassiveDiscoveryService dhcpService = dhcpEnabledService();
        when(dhcpCapture.capture(anyString(), anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor(null, "52:54:00:12:34:56", null, null, "eth0", "laptop-7", null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.DHCP));
        PassiveDiscoveryResponse resp = dhcpService.sweep(req);

        ArgumentCaptor<List<Discovery>> captor = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captor.capture());
        List<Discovery> batch = captor.getValue();
        assertThat(batch).hasSize(1);
        assertThat(batch.get(0).ipAddress())
            .as("MAC-only DHCP client must be keyed by the synthetic placeholder IP")
            .isEqualTo("mac:52-54-00-12-34-56");
        assertThat(batch.get(0).macAddress()).isEqualTo("52:54:00:12:34:56");
        assertThat(resp.perSourceCount().get(DiscoverySource.DHCP)).isEqualTo(1);
        assertThat(resp.discovered()).isEqualTo(1);
    }

    /**
     * S5. Capability failure: a PcapNativeException from the capture must surface as a
     * DiscoveryUnavailableException carrying the DHCP-specific message, and the sweep
     * row must finish UNAVAILABLE (mirrors the PCAP/LLDP/CDP wrap contract).
     */
    @Test
    void sweep_dhcpPcapNativeException_wrappedInDiscoveryUnavailableAndRowUnavailable() throws Exception {
        PassiveDiscoveryService dhcpService = dhcpEnabledService();
        when(dhcpCapture.capture(anyString(), anyInt()))
            .thenThrow(new org.pcap4j.core.PcapNativeException("no pcap"));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.DHCP));
        assertThatThrownBy(() -> dhcpService.sweep(req))
            .isInstanceOf(DiscoveryUnavailableException.class)
            .hasMessageContaining("DHCP capture failed on interface 'eth0'");

        verify(recorder).finish(eq(42L), eq("UNAVAILABLE"), eq(0), eq(0), isNull(), any());
    }

    /**
     * S6. THE common-router pin: ARP sees the router (MAC + real IP), DHCP hears its
     * gateway-hint row (same IP, no MAC). reconcileMacPrimacy drops the IP-keyed hint
     * row in favor of the MAC-keyed ARP row — but the hint must SURVIVE onto the kept
     * row, or the single most common hint path silently dies.
     */
    @Test
    @SuppressWarnings("unchecked")
    void sweep_arpRowAndDhcpGatewayHintSameIp_hintSurvivesReconcile() throws Exception {
        PassiveDiscoveryService dhcpService = dhcpEnabledService();
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("192.168.1.1", "aa:bb:cc:dd:ee:01", "0x1", "0x2", "eth0", null, null)
        ));
        when(dhcpCapture.capture(anyString(), anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor("192.168.1.1", null, null, null, "eth0", null, RoleHint.GATEWAY)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(
            "eth0", 5, List.of(DiscoverySource.ARP, DiscoverySource.DHCP));
        dhcpService.sweep(req);

        ArgumentCaptor<List<Discovery>> captor = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captor.capture());
        List<Discovery> batch = captor.getValue();
        assertThat(batch).hasSize(1);
        assertThat(batch.get(0).macAddress())
            .as("the MAC-keyed ARP row wins the reconcile")
            .isEqualTo("aa:bb:cc:dd:ee:01");
        assertThat(batch.get(0).roleHint())
            .as("the dropped IP-keyed row's GATEWAY hint must survive onto the kept row")
            .isEqualTo(RoleHint.GATEWAY);
    }

    /**
     * S7. withoutMac rank merge: two MAC-less DHCP hint rows for the same IP (gateway
     * hint + dns hint) must fold into ONE Discovery carrying the higher-ranked GATEWAY —
     * in both arrival orders (last-writer would drop a hint in one of them).
     */
    @Test
    @SuppressWarnings("unchecked")
    void sweep_gatewayAndDnsHintsSameIp_bothOrders_rankMaxWins() throws Exception {
        DiscoveredNeighbor gatewayHint =
            new DiscoveredNeighbor("192.168.1.1", null, null, null, "eth0", null, RoleHint.GATEWAY);
        DiscoveredNeighbor dnsHint =
            new DiscoveredNeighbor("192.168.1.1", null, null, null, "eth0", null, RoleHint.DNS_SERVER);
        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.DHCP));

        // Order A: gateway first, dns second.
        PassiveDiscoveryService dhcpService = dhcpEnabledService();
        when(dhcpCapture.capture(anyString(), anyInt())).thenReturn(List.of(gatewayHint, dnsHint));
        dhcpService.sweep(req);

        ArgumentCaptor<List<Discovery>> captorA = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captorA.capture());
        assertThat(captorA.getValue()).hasSize(1);
        assertThat(captorA.getValue().get(0).roleHint())
            .as("gateway-then-dns: rank merge keeps GATEWAY")
            .isEqualTo(RoleHint.GATEWAY);

        // Order B: dns first, gateway second.
        org.mockito.Mockito.clearInvocations(upsertService, dhcpCapture, recorder);
        when(dhcpCapture.capture(anyString(), anyInt())).thenReturn(List.of(dnsHint, gatewayHint));
        dhcpService.sweep(req);

        ArgumentCaptor<List<Discovery>> captorB = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captorB.capture());
        assertThat(captorB.getValue()).hasSize(1);
        assertThat(captorB.getValue().get(0).roleHint())
            .as("dns-then-gateway: the incoming GATEWAY must upgrade, not be dropped")
            .isEqualTo(RoleHint.GATEWAY);
    }

    /**
     * S8. mergeOnMac keeps hints: a DHCP server row (real IP + MAC + DHCP_SERVER hint)
     * collides on MAC with an LLDP MAC-only placeholder. The real-IP row wins the merge
     * in both orders, and the hint must ride the winner.
     */
    @Test
    @SuppressWarnings("unchecked")
    void sweep_dhcpServerRowVsLldpPlaceholderSameMac_bothOrders_hintSurvivesMerge() throws Exception {
        DiscoveredNeighbor dhcpServer = new DiscoveredNeighbor(
            "10.0.0.5", "00:11:22:33:44:55", null, null, "eth0", null, RoleHint.DHCP_SERVER);
        DiscoveredNeighbor lldpPlaceholder = new DiscoveredNeighbor(
            null, "00:11:22:33:44:55", null, null, "eth0", "switch01", null);

        // Order A: DHCP collected first (sources listed DHCP, LLDP).
        PassiveDiscoveryService serviceA = lldpAndDhcpEnabledService();
        when(dhcpCapture.capture(anyString(), anyInt())).thenReturn(List.of(dhcpServer));
        when(lldpCapture.capture(anyString(), anyInt())).thenReturn(List.of(lldpPlaceholder));
        serviceA.sweep(new PassiveDiscoveryRequest(
            "eth0", 5, List.of(DiscoverySource.DHCP, DiscoverySource.LLDP)));

        ArgumentCaptor<List<Discovery>> captorA = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captorA.capture());
        assertThat(captorA.getValue()).hasSize(1);
        assertThat(captorA.getValue().get(0).ipAddress()).isEqualTo("10.0.0.5");
        assertThat(captorA.getValue().get(0).roleHint())
            .as("DHCP-then-LLDP: the winner's own hint must not be erased by the placeholder")
            .isEqualTo(RoleHint.DHCP_SERVER);

        // Order B: LLDP placeholder collected first.
        org.mockito.Mockito.clearInvocations(upsertService, dhcpCapture, lldpCapture, recorder);
        serviceA.sweep(new PassiveDiscoveryRequest(
            "eth0", 5, List.of(DiscoverySource.LLDP, DiscoverySource.DHCP)));

        ArgumentCaptor<List<Discovery>> captorB = ArgumentCaptor.forClass(List.class);
        verify(upsertService).upsertAll(captorB.capture());
        assertThat(captorB.getValue()).hasSize(1);
        assertThat(captorB.getValue().get(0).ipAddress())
            .as("the real-IP row must replace the earlier placeholder")
            .isEqualTo("10.0.0.5");
        assertThat(captorB.getValue().get(0).roleHint())
            .as("LLDP-then-DHCP: the hint must ride the real-IP winner through mergeOnMac")
            .isEqualTo(RoleHint.DHCP_SERVER);
        assertThat(captorB.getValue().get(0).hostname())
            .as("the placeholder's hostname still backfills")
            .isEqualTo("switch01");
    }
}
