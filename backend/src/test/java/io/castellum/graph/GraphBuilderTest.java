package io.castellum.graph;

import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.Criticality;
import io.castellum.risk.EpssScoreRepository;
import io.castellum.risk.KevEntryRepository;
import org.jgrapht.Graph;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class GraphBuilderTest {

    private DeviceRepository deviceRepo;
    private NetworkServiceRepository serviceRepo;
    private CveMatcher cveMatcher;
    private EpssScoreRepository epssRepo;
    private KevEntryRepository kevRepo;
    private GraphProperties properties;
    private GraphBuilder builder;

    @BeforeEach
    void setUp() {
        deviceRepo = mock(DeviceRepository.class);
        serviceRepo = mock(NetworkServiceRepository.class);
        cveMatcher = mock(CveMatcher.class);
        epssRepo = mock(EpssScoreRepository.class);
        kevRepo = mock(KevEntryRepository.class);
        properties = new GraphProperties();
        properties.setSubnetCap(64);
        properties.setVulnsPerPairCap(5);
        when(serviceRepo.findByDeviceId(any())).thenReturn(List.of());
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of());
        when(epssRepo.findByCveId(anyString())).thenReturn(Optional.empty());
        when(kevRepo.existsByCveId(anyString())).thenReturn(false);
        builder = new GraphBuilder(deviceRepo, serviceRepo, cveMatcher, epssRepo, kevRepo, properties);
    }

    private Device device(long id, String ip) {
        return new Device(id, ip, null, null, Instant.EPOCH, Instant.EPOCH, Criticality.MEDIUM);
    }

    @Test
    void sameSubnetEdgesAreBidirectional() {
        Device a = device(1L, "10.0.0.10");
        Device b = device(2L, "10.0.0.20");
        when(deviceRepo.findAll()).thenReturn(List.of(a, b));

        Graph<DeviceVertex, AttackEdge> g = builder.build();

        DeviceVertex va = new DeviceVertex(1L, "10.0.0.10");
        DeviceVertex vb = new DeviceVertex(2L, "10.0.0.20");
        AttackEdge ab = g.getEdge(va, vb);
        AttackEdge ba = g.getEdge(vb, va);
        assertThat(ab).isNotNull();
        assertThat(ba).isNotNull();
        assertThat(ab.getType()).isEqualTo(EdgeType.SAME_SUBNET);
        assertThat(g.getEdgeWeight(ab)).isEqualTo(1.0);
    }

    @Test
    void crossSubnetDevicesAreNotConnected() {
        Device a = device(1L, "10.0.0.10");
        Device b = device(2L, "10.0.1.10");
        when(deviceRepo.findAll()).thenReturn(List.of(a, b));

        Graph<DeviceVertex, AttackEdge> g = builder.build();

        assertThat(g.edgeSet()).isEmpty();
    }

    @Test
    void subnetCapEnforced() {
        properties.setSubnetCap(2);
        List<Device> devs = new ArrayList<>();
        devs.add(device(1L, "10.0.0.10"));
        devs.add(device(2L, "10.0.0.11"));
        devs.add(device(3L, "10.0.0.12"));
        when(deviceRepo.findAll()).thenReturn(devs);

        Graph<DeviceVertex, AttackEdge> g = builder.build();

        assertThat(g.edgeSet()).isEmpty();
    }

    @Test
    void nonIpv4DeviceExcludedFromSubnetGrouping() {
        Device a = device(1L, "fe80::1");
        Device b = device(2L, "fe80::2");
        when(deviceRepo.findAll()).thenReturn(List.of(a, b));

        Graph<DeviceVertex, AttackEdge> g = builder.build();

        assertThat(g.edgeSet()).isEmpty();
    }

    @Test
    void vulnEdgeWeightInvertsCompositeScore() {
        Device peer = device(1L, "10.0.0.10");
        Device target = device(2L, "10.0.0.20");
        when(deviceRepo.findAll()).thenReturn(List.of(peer, target));

        NetworkService svc = new NetworkService(10L, 2L, 22, "tcp", "openssh", "8.2", Instant.EPOCH);
        when(serviceRepo.findByDeviceId(2L)).thenReturn(List.of(svc));

        Cve cve = new Cve();
        cve.setCveId("CVE-TEST-1");
        cve.setCvssV31Score(new BigDecimal("9.5"));
        cve.setLastModified(Instant.EPOCH);
        cve.setRawJson("{}");
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(cve));

        Graph<DeviceVertex, AttackEdge> g = builder.build();

        DeviceVertex vs = new DeviceVertex(1L, "10.0.0.10");
        DeviceVertex vt = new DeviceVertex(2L, "10.0.0.20");
        AttackEdge vulnEdge = g.getAllEdges(vs, vt).stream()
            .filter(e -> e.getType() == EdgeType.EXPLOITABLE_VULN)
            .findFirst()
            .orElseThrow();
        // weight = 11.0 - riskContribution invariant
        assertThat(g.getEdgeWeight(vulnEdge)).isCloseTo(11.0 - vulnEdge.getRiskContribution(), within(0.001));
        assertThat(vulnEdge.getCveId()).isEqualTo("CVE-TEST-1");
    }

    @Test
    void vulnEdgeRiskContributionEqualsCompositeScore() {
        Device peer = device(1L, "10.0.0.10");
        Device target = device(2L, "10.0.0.20");
        when(deviceRepo.findAll()).thenReturn(List.of(peer, target));

        NetworkService svc = new NetworkService(10L, 2L, 22, "tcp", "openssh", "8.2", Instant.EPOCH);
        when(serviceRepo.findByDeviceId(2L)).thenReturn(List.of(svc));

        Cve cve = new Cve();
        cve.setCveId("CVE-TEST-2");
        cve.setCvssV31Score(new BigDecimal("8.0"));
        cve.setLastModified(Instant.EPOCH);
        cve.setRawJson("{}");
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(cve));

        Graph<DeviceVertex, AttackEdge> g = builder.build();

        DeviceVertex vs = new DeviceVertex(1L, "10.0.0.10");
        DeviceVertex vt = new DeviceVertex(2L, "10.0.0.20");
        AttackEdge vulnEdge = g.getAllEdges(vs, vt).stream()
            .filter(e -> e.getType() == EdgeType.EXPLOITABLE_VULN)
            .findFirst()
            .orElseThrow();
        // riskContribution should be equal to compositeScore used to build edge weight
        assertThat(g.getEdgeWeight(vulnEdge)).isCloseTo(11.0 - vulnEdge.getRiskContribution(), within(0.001));
    }

    @Test
    void topNVulnsRetainedPerDevicePair() {
        properties.setVulnsPerPairCap(5);
        Device peer = device(1L, "10.0.0.10");
        Device target = device(2L, "10.0.0.20");
        when(deviceRepo.findAll()).thenReturn(List.of(peer, target));

        NetworkService svc = new NetworkService(10L, 2L, 22, "tcp", "openssh", "8.2", Instant.EPOCH);
        when(serviceRepo.findByDeviceId(2L)).thenReturn(List.of(svc));

        List<Cve> seven = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            Cve c = new Cve();
            c.setCveId("CVE-TEST-" + i);
            c.setCvssV31Score(new BigDecimal(i + 1));
            c.setLastModified(Instant.EPOCH);
            c.setRawJson("{}");
            seven.add(c);
        }
        when(cveMatcher.findVulnerable(anyString())).thenReturn(seven);

        Graph<DeviceVertex, AttackEdge> g = builder.build();

        DeviceVertex vs = new DeviceVertex(1L, "10.0.0.10");
        DeviceVertex vt = new DeviceVertex(2L, "10.0.0.20");
        long vulnEdges = g.getAllEdges(vs, vt).stream()
            .filter(e -> e.getType() == EdgeType.EXPLOITABLE_VULN).count();
        assertThat(vulnEdges).isEqualTo(5);
    }

    @Test
    void compositeScoreMemoizedPerBuild() {
        // Two same-subnet peers and one target — the per-(cve, deviceId) composite for the target
        // should be computed once; EPSS and KEV repos are queried only on first miss.
        Device peerA = device(1L, "10.0.0.10");
        Device peerB = device(2L, "10.0.0.20");
        Device target = device(3L, "10.0.0.30");
        when(deviceRepo.findAll()).thenReturn(List.of(peerA, peerB, target));

        NetworkService svc = new NetworkService(10L, 3L, 22, "tcp", "openssh", "8.2", Instant.EPOCH);
        when(serviceRepo.findByDeviceId(3L)).thenReturn(List.of(svc));

        Cve cve = new Cve();
        cve.setCveId("CVE-MEMO-1");
        cve.setCvssV31Score(new BigDecimal("7.5"));
        cve.setLastModified(Instant.EPOCH);
        cve.setRawJson("{}");
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(cve));

        builder.build();

        // EPSS + KEV repos called exactly once for (CVE-MEMO-1, deviceId=3) despite two peers.
        verify(epssRepo, times(1)).findByCveId("CVE-MEMO-1");
        verify(kevRepo, times(1)).existsByCveId("CVE-MEMO-1");
    }

    private static org.assertj.core.data.Offset<Double> within(double tolerance) {
        return org.assertj.core.data.Offset.offset(tolerance);
    }
}
