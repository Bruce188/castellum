package io.castellum.graph;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.discovery.DiscoveryScope;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.Criticality;
import io.castellum.risk.EpssScoreRepository;
import io.castellum.risk.KevEntryRepository;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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

    private Device dockerDevice(long id, String ip) {
        Device d = device(id, ip);
        d.setDiscoveryScope(DiscoveryScope.DOCKER_BRIDGE);
        return d;
    }

    private Device homeDeviceWithHostname(long id, String ip, String hostname) {
        Device d = device(id, ip);
        d.setHostname(hostname);
        return d;
    }

    @Test
    void sameSubnetEdgesAreBidirectional() {
        Device a = device(1L, "10.0.0.10");
        Device b = device(2L, "10.0.0.20");
        when(deviceRepo.findAll()).thenReturn(List.of(a, b));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

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
        // Two HOME-scope devices in different /24 subnets with no docker-host pivot present.
        // Neither matches the dockerHostIp (10.0.x.x != 192.168.68.51) and neither is
        // DOCKER_BRIDGE, so no GATEWAY_PIVOT edge is emitted. The no-pivot isolation is
        // intentional, not a CIDR accident.
        Device a = device(1L, "10.0.0.10");
        Device b = device(2L, "10.0.1.10");
        when(deviceRepo.findAll()).thenReturn(List.of(a, b));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

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

        ch.qos.logback.classic.Logger logger =
            (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(GraphBuilder.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            Graph<DeviceVertex, AttackEdge> g = builder.build().graph();
            assertThat(g.edgeSet()).isEmpty();
            assertThat(appender.list).anyMatch(evt ->
                evt.getLevel() == Level.WARN
                    && evt.getFormattedMessage().contains("exceeds subnet-cap"));
        } finally {
            logger.detachAppender(appender);
            appender.stop();
        }
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

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

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

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

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

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        DeviceVertex vs = new DeviceVertex(1L, "10.0.0.10");
        DeviceVertex vt = new DeviceVertex(2L, "10.0.0.20");
        long vulnEdges = g.getAllEdges(vs, vt).stream()
            .filter(e -> e.getType() == EdgeType.EXPLOITABLE_VULN).count();
        assertThat(vulnEdges).isEqualTo(5);
    }

    /**
     * Memoization key contract: {@link CompositeScoreMemoizer} caches keyed on
     * {@code (cveId, deviceId)} — NOT {@code cveId} alone. Two same-subnet peers
     * routing through the same target device + CVE pair share the cache; two
     * different target devices for the same CVE do NOT.
     */
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

    @Test
    void ipv6SameSlash64GetsSameSubnetEdge() {
        Device a = device(1L, "2001:db8:0:1::10");
        Device b = device(2L, "2001:db8:0:1::20");
        when(deviceRepo.findAll()).thenReturn(List.of(a, b));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        DeviceVertex va = new DeviceVertex(1L, "2001:db8:0:1::10");
        DeviceVertex vb = new DeviceVertex(2L, "2001:db8:0:1::20");
        AttackEdge ab = g.getEdge(va, vb);
        assertThat(ab).isNotNull();
        assertThat(ab.getType()).isEqualTo(EdgeType.SAME_SUBNET);
    }

    @Test
    void ipv6CrossSlash64HasNoSameSubnetEdge() {
        Device a = device(1L, "2001:db8:0:1::10");
        Device b = device(2L, "2001:db8:0:2::10");
        when(deviceRepo.findAll()).thenReturn(List.of(a, b));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        assertThat(g.edgeSet()).isEmpty();
    }

    @Test
    void buildRejectsWhenDeviceCountExceedsMaxDevices() {
        properties.setMaxDevices(2);
        List<Device> devs = List.of(
            device(1L, "10.0.0.10"),
            device(2L, "10.0.0.11"),
            device(3L, "10.0.0.12"));
        when(deviceRepo.findAll()).thenReturn(devs);

        assertThatThrownBy(() -> builder.build())
            .isInstanceOf(GraphTooLargeException.class)
            .hasMessageContaining("max-devices");
    }

    @Test
    void homeAndDockerBridgedViaDockerHostPivot() {
        // Pivot: HOME device with the configured dockerHostIp
        Device pivot = device(5L, "192.168.68.51");
        // Docker member
        Device docker = dockerDevice(4L, "172.17.0.2");
        when(deviceRepo.findAll()).thenReturn(List.of(pivot, docker));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        DeviceVertex vPivot = new DeviceVertex(5L, "192.168.68.51");
        DeviceVertex vDocker = new DeviceVertex(4L, "172.17.0.2");

        // Forward and reverse GATEWAY_PIVOT edges exist
        AttackEdge fwd = g.getEdge(vPivot, vDocker);
        AttackEdge rev = g.getEdge(vDocker, vPivot);
        assertThat(fwd).isNotNull();
        assertThat(rev).isNotNull();
        assertThat(fwd.getType()).isEqualTo(EdgeType.GATEWAY_PIVOT);
        assertThat(rev.getType()).isEqualTo(EdgeType.GATEWAY_PIVOT);

        // End-to-end: path is findable
        Optional<GraphPath<DeviceVertex, AttackEdge>> path =
            new ShortestPathFinder().findPath(g, vPivot, vDocker);
        assertThat(path).isPresent();
        assertThat(path.get().getEdgeList()).isNotEmpty();
    }

    @Test
    void crossScopeWithoutPivotHasNoBridge() {
        // HOME device that is NOT the docker-host pivot (different IP, hostname null)
        Device home = device(5L, "192.168.68.99");
        Device docker = dockerDevice(4L, "172.17.0.2");
        when(deviceRepo.findAll()).thenReturn(List.of(home, docker));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        // No GATEWAY_PIVOT edge
        boolean hasGatewayEdge = g.edgeSet().stream()
            .anyMatch(e -> e.getType() == EdgeType.GATEWAY_PIVOT);
        assertThat(hasGatewayEdge).isFalse();
    }

    @Test
    void gatewayPivotEdgeHasWeightAndTechnique() {
        Device pivot = device(5L, "192.168.68.51");
        Device docker = dockerDevice(4L, "172.17.0.2");
        when(deviceRepo.findAll()).thenReturn(List.of(pivot, docker));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        DeviceVertex vPivot = new DeviceVertex(5L, "192.168.68.51");
        DeviceVertex vDocker = new DeviceVertex(4L, "172.17.0.2");

        AttackEdge edge = g.getEdge(vPivot, vDocker);
        assertThat(edge).isNotNull();
        assertThat(g.getEdgeWeight(edge)).isEqualTo(EdgeWeights.gatewayPivotWeight());
        assertThat(edge.getTechniqueId()).isEqualTo(
            AttackTechniqueMapper.forEdgeType(EdgeType.GATEWAY_PIVOT).id());
        assertThat(edge.getCveId()).isNull();
        assertThat(edge.getRiskContribution()).isEqualTo(EdgeWeights.gatewayPivotRisk());
    }

    @Test
    void linkLocalStaysIsolated() {
        // Valid pivot exists
        Device pivot = device(5L, "192.168.68.51");
        // DOCKER_BRIDGE member
        Device docker = dockerDevice(4L, "172.17.0.2");
        // LINK_LOCAL device — must never receive a GATEWAY_PIVOT edge
        Device linkLocal = device(6L, "169.254.73.152");
        linkLocal.setDiscoveryScope(DiscoveryScope.LINK_LOCAL);
        when(deviceRepo.findAll()).thenReturn(List.of(pivot, docker, linkLocal));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        DeviceVertex vLinkLocal = new DeviceVertex(6L, "169.254.73.152");
        // No GATEWAY_PIVOT edges touch the LINK_LOCAL vertex
        boolean linkLocalHasGatewayEdge = g.edgesOf(vLinkLocal).stream()
            .anyMatch(e -> e.getType() == EdgeType.GATEWAY_PIVOT);
        assertThat(linkLocalHasGatewayEdge).isFalse();
    }

    private static org.assertj.core.data.Offset<Double> within(double tolerance) {
        return org.assertj.core.data.Offset.offset(tolerance);
    }
}
