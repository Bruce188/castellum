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
    @Mock private LldpDecoder lldpDecoder;
    @Mock private LldpCapture lldpCapture;
    @Mock private CdpDecoder cdpDecoder;
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
            arpFactory, mdnsProbe, pcapSniffer, lldpDecoder, lldpCapture, cdpDecoder,
            connTableReader, gatewayProbe,
            upsertService, auditService, recorder,
            false /* lldpEnabled */,
            false /* cdpEnabled */,
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
            new DiscoveredNeighbor("10.0.9.1", "aa:bb:cc:dd:ee:01", "0x1", "0x2", "eth0", null)
        ));
        when(gatewayProbe.probe()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.9.1", null, null, null, "eth0", null)
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
            new DiscoveredNeighbor("10.0.9.2", "aa:bb:cc:dd:ee:02", "0x1", "0x2", "eth0", null)
        ));
        when(mdnsProbe.probe(anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.9.2", null, null, null, null, "printer.local")
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
            new DiscoveredNeighbor("10.0.9.5", "aa:bb:cc:dd:ee:05", "0x1", "0x2", null, null)
        ));
        // GATEWAY row: null-MAC, iface="eth0"
        when(gatewayProbe.probe()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.9.5", null, null, null, "eth0", null)
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
            arpFactory, mdnsProbe, pcapSniffer, lldpDecoder, lldpCapture, cdpDecoder,
            connTableReader, gatewayProbe,
            upsertService, auditService, recorder,
            false, false, false, true, clock);

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest("eth0", 5, List.of(DiscoverySource.PCAP));
        PassiveDiscoveryResponse resp = disabled.sweep(req);

        assertThat(resp.discovered()).isEqualTo(0);
        org.mockito.Mockito.verifyNoInteractions(pcapSniffer);
    }

    @Test
    void sweep_connTableDisabledByFlag_skippedSilentlyEvenWhenRequested() throws Exception {
        // Build a service variant with connTableEnabled=false
        PassiveDiscoveryService disabled = new PassiveDiscoveryService(
            arpFactory, mdnsProbe, pcapSniffer, lldpDecoder, lldpCapture, cdpDecoder,
            connTableReader, gatewayProbe,
            upsertService, auditService, recorder,
            false, false, true, false, clock);

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(null, 5, List.of(DiscoverySource.CONN_TABLE));
        PassiveDiscoveryResponse resp = disabled.sweep(req);

        assertThat(resp.discovered()).isEqualTo(0);
        org.mockito.Mockito.verifyNoInteractions(connTableReader);
    }

    @Test
    void sweep_connTableEnabled_collectsRemoteEndpoints() throws Exception {
        when(connTableReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("8.8.8.8", null, null, null, null, null),
            new DiscoveredNeighbor("140.82.121.4", null, null, null, null, null)
        ));

        PassiveDiscoveryRequest req = new PassiveDiscoveryRequest(null, 5, List.of(DiscoverySource.CONN_TABLE));
        PassiveDiscoveryResponse resp = service.sweep(req);

        assertThat(resp.discovered()).isEqualTo(2);
        assertThat(resp.perSourceCount().get(DiscoverySource.CONN_TABLE)).isEqualTo(2);
    }

    @Test
    void sweep_gatewaySource_dispatchesProbe() throws Exception {
        when(gatewayProbe.probe()).thenReturn(List.of(
            new DiscoveredNeighbor("192.168.1.1", null, null, null, "eth0", null)
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

    /**
     * AC3 — success path: recorder.finish receives the real neighbor_count (not 0) and the
     * observed iface derived from the collected neighbors' iface field.
     */
    @Test
    void sweep_arpSuccess_recordsRealNeighborCountAndObservedIface() throws Exception {
        when(arpReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.0.1", "aa:00:00:00:00:01", "0x1", "0x2", "eth0", null),
            new DiscoveredNeighbor("10.0.0.2", "aa:00:00:00:00:02", "0x1", "0x2", "eth0", null),
            new DiscoveredNeighbor("10.0.0.3", "aa:00:00:00:00:03", "0x1", "0x2", "eth0", null)
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
            new DiscoveredNeighbor("10.0.8.1", "dd:00:00:00:00:01", "0x1", "0x2", "eth0", null)
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
            new DiscoveredNeighbor("10.0.8.1", "dd:00:00:00:00:01", "0x1", "0x2", "eth0", null)
        ));
        when(connTableReader.read()).thenReturn(List.of(
            new DiscoveredNeighbor("8.8.8.8", null, null, null, null, null)
        ));
        when(gatewayProbe.probe()).thenReturn(List.of(
            new DiscoveredNeighbor("10.0.8.254", null, null, null, "eth0", null)
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
            new DiscoveredNeighbor("10.0.9.1", "ee:00:00:00:00:01", "0x1", "0x2", "eth0", null)
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
            arpFactory, mdnsProbe, pcapSniffer, lldpDecoder, lldpCapture, cdpDecoder,
            connTableReader, gatewayProbe,
            upsertService, auditService, recorder,
            true /* lldpEnabled */, false, true, true, clock);
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
            new DiscoveredNeighbor("192.168.1.10", "aa:bb:cc:dd:ee:0e", null, null, "eth0", "switch01")
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
            new DiscoveredNeighbor(null, "aa:bb:cc:dd:ee:ff", null, null, "eth0", null)
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
            new DiscoveredNeighbor(null, null, null, null, "eth0", "ghost-switch")
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
            new DiscoveredNeighbor("10.0.0.5", "aa:bb:cc:dd:ee:ff", "0x1", "0x2", "eth0", null)
        ));
        when(lldpCapture.capture(anyString(), anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor(null, "aa:bb:cc:dd:ee:ff", null, null, "eth0", "switch01")
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
            new DiscoveredNeighbor("10.0.0.5", "aa:bb:cc:dd:ee:ff", "0x1", "0x2", "eth0", null)
        ));
        when(lldpCapture.capture(anyString(), anyInt())).thenReturn(List.of(
            new DiscoveredNeighbor(null, "aa:bb:cc:dd:ee:ff", null, null, "eth0", "switch01")
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
}
