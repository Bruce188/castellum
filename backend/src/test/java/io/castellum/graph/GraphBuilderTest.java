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
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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

    private Device publicDevice(long id, String ip) {
        Device d = device(id, ip);
        d.setDiscoveryScope(DiscoveryScope.PUBLIC);
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

    // ────────────────────────────────────────────────────────────────────────
    // AC3 — pivot detection by IP only; hostname string match removed
    // ────────────────────────────────────────────────────────────────────────

    /**
     * AC3: pivot is detected by the configured dockerHostIp alone. A HOME device at that IP
     * with a null hostname (real-world post-fix state) must still work as the pivot.
     */
    @Test
    void gatewayPivot_detectedByIp_hostnameNull() {
        // pivot: HOME device at docker-host IP, hostname = null (bridge alias was filtered)
        Device pivot = device(5L, "192.168.68.51");
        // pivot has no hostname set (remains null from device())
        Device docker = dockerDevice(4L, "172.17.0.2");
        when(deviceRepo.findAll()).thenReturn(List.of(pivot, docker));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        DeviceVertex vPivot = new DeviceVertex(5L, "192.168.68.51");
        DeviceVertex vDocker = new DeviceVertex(4L, "172.17.0.2");

        assertThat(g.getEdge(vPivot, vDocker))
            .as("pivot detected by IP with null hostname must still bridge docker")
            .isNotNull();
        assertThat(g.getEdge(vPivot, vDocker).getType()).isEqualTo(EdgeType.GATEWAY_PIVOT);
    }

    /**
     * AC3: pivot is detected by IP even when it has a real hostname (not the bridge alias).
     */
    @Test
    void gatewayPivot_detectedByIp_hostnameRealName() {
        Device pivot = homeDeviceWithHostname(5L, "192.168.68.51", "operators-laptop");
        Device docker = dockerDevice(4L, "172.17.0.2");
        when(deviceRepo.findAll()).thenReturn(List.of(pivot, docker));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        DeviceVertex vPivot = new DeviceVertex(5L, "192.168.68.51");
        DeviceVertex vDocker = new DeviceVertex(4L, "172.17.0.2");

        assertThat(g.getEdge(vPivot, vDocker))
            .as("pivot with real hostname still bridges docker")
            .isNotNull();
    }

    /**
     * AC3 / AC5(c): a HOME device whose hostname is "host.docker.internal" but whose IP does NOT
     * match the configured docker-host IP must NOT be treated as a pivot.
     * (Hostname-string match is removed; IP is the sole criterion.)
     */
    @Test
    void gatewayPivot_hostnameAliasAloneIsNotSufficient_ipMustMatch() {
        // device with the alias hostname but a different IP
        Device wrongIp = homeDeviceWithHostname(5L, "192.168.68.99", "host.docker.internal");
        Device docker = dockerDevice(4L, "172.17.0.2");
        when(deviceRepo.findAll()).thenReturn(List.of(wrongIp, docker));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        boolean hasGatewayEdge = g.edgeSet().stream()
            .anyMatch(e -> e.getType() == EdgeType.GATEWAY_PIVOT);
        assertThat(hasGatewayEdge)
            .as("hostname alias alone must not qualify as docker-host pivot")
            .isFalse();
    }

    // ────────────────────────────────────────────────────────────────────────
    // Multi-pivot: per-origin GATEWAY_PIVOT partitioning
    // ────────────────────────────────────────────────────────────────────────

    /**
     * Two origins: "local" pivot at dockerHostIp and a remote pivot at 192.168.1.50.
     * Each pivot bridges ONLY its own partition's docker member.
     * Cross-origin GATEWAY_PIVOT edges must NOT exist.
     */
    @Test
    void multiPivot_eachOriginBridgesOnlyItsOwnDockerMember() {
        // Local origin — pivot and its docker member
        Device localPivot = device(5L, "192.168.68.51");          // HOME, local
        Device localDocker = dockerDevice(4L, "172.17.0.2");      // DOCKER_BRIDGE, originHostIp="local" (entity default)

        // Remote origin — pivot at 192.168.1.50 and its docker member
        Device remotePivot = device(10L, "192.168.1.50");         // HOME
        Device remoteDocker = dockerDevice(11L, "172.18.0.2");    // DOCKER_BRIDGE, originHostIp="192.168.1.50"
        remoteDocker.setOriginHostIp("192.168.1.50");

        when(deviceRepo.findAll()).thenReturn(List.of(localPivot, localDocker, remotePivot, remoteDocker));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        DeviceVertex vLocalPivot  = new DeviceVertex(5L,  "192.168.68.51");
        DeviceVertex vLocalDocker = new DeviceVertex(4L,  "172.17.0.2");
        DeviceVertex vRemPivot    = new DeviceVertex(10L, "192.168.1.50");
        DeviceVertex vRemDocker   = new DeviceVertex(11L, "172.18.0.2");

        // Each pivot bridges its own member
        assertThat(g.getEdge(vLocalPivot, vLocalDocker)).as("local pivot → local docker").isNotNull();
        assertThat(g.getEdge(vLocalDocker, vLocalPivot)).as("local docker → local pivot").isNotNull();
        assertThat(g.getEdge(vRemPivot, vRemDocker)).as("remote pivot → remote docker").isNotNull();
        assertThat(g.getEdge(vRemDocker, vRemPivot)).as("remote docker → remote pivot").isNotNull();

        // Cross-origin GATEWAY_PIVOT edges must NOT exist
        assertThat(g.getEdge(vLocalPivot, vRemDocker))
            .as("local pivot must NOT bridge remote docker")
            .isNull();
        assertThat(g.getEdge(vRemPivot, vLocalDocker))
            .as("remote pivot must NOT bridge local docker")
            .isNull();
    }

    /**
     * Per-partition subnetCap: one origin exceeds cap (skipped), a second origin under cap
     * still emits edges — proves the cap is per-partition, not global.
     */
    @Test
    void multiPivot_perPartitionSubnetCap_overCapPartitionSkippedOtherEmits() {
        properties.setSubnetCap(1);   // cap = 1 member per partition

        // Local partition: 2 docker members — exceeds cap → skipped
        Device localPivot = device(5L, "192.168.68.51");
        Device localDocker1 = dockerDevice(4L, "172.17.0.2");
        Device localDocker2 = dockerDevice(6L, "172.17.0.3");

        // Remote partition: 1 docker member — within cap → emits
        Device remotePivot = device(10L, "192.168.1.50");
        Device remoteDocker = dockerDevice(11L, "172.18.0.2");
        remoteDocker.setOriginHostIp("192.168.1.50");

        when(deviceRepo.findAll()).thenReturn(List.of(localPivot, localDocker1, localDocker2, remotePivot, remoteDocker));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        DeviceVertex vLocalPivot  = new DeviceVertex(5L,  "192.168.68.51");
        DeviceVertex vLocalD1     = new DeviceVertex(4L,  "172.17.0.2");
        DeviceVertex vRemPivot    = new DeviceVertex(10L, "192.168.1.50");
        DeviceVertex vRemDocker   = new DeviceVertex(11L, "172.18.0.2");

        // Local partition over cap → no GATEWAY_PIVOT
        assertThat(g.getEdge(vLocalPivot, vLocalD1)).as("over-cap local partition must not emit edges").isNull();

        // Remote partition within cap → emits
        assertThat(g.getEdge(vRemPivot, vRemDocker)).as("under-cap remote partition must emit edges").isNotNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // PUBLIC-scope isolation — PUBLIC devices are vertices but never get edges
    // ────────────────────────────────────────────────────────────────────────

    /**
     * PUBLIC-scope devices must appear in the graph as vertices but be FULLY isolated:
     * zero edges of ANY type (SAME_SUBNET, GATEWAY_PIVOT, EXPLOITABLE_VULN), either
     * direction. The fixture stacks all three edge sources against the PUBLIC device:
     * <ul>
     *   <li>it shares a /24 with two HOME devices — would receive SAME_SUBNET edges
     *       from the scope-blind subnet bucketing;</li>
     *   <li>it runs a vulnerable service with a matching CVE — would receive inbound
     *       EXPLOITABLE_VULN edges from its same-subnet peers;</li>
     *   <li>a HOME peer in the same /24 ALSO runs a vulnerable service — if PUBLIC
     *       leaked into the bucket, the pass would draw an outbound pub→home edge,
     *       so the PUBLIC-as-source direction is constructible-if-broken too;</li>
     *   <li>a DOCKER_BRIDGE member's originHostIp equals its IP — would make it a
     *       remote GATEWAY_PIVOT pivot if scope were not checked.</li>
     * </ul>
     * Isolation must also be surgical: the HOME peers in the same /24 keep their own
     * SAME_SUBNET edges.
     *
     * <p>The PUBLIC device deliberately sits on a private 10.0.0.0/24 address. Real
     * PUBLIC devices carry public IPs, but parking one inside the HOME /24 is the
     * adversarial worst case for the v4 bucketing guard — if scope were ignored,
     * every edge source would fire at once.
     */
    @Test
    void publicStaysFullyIsolated() {
        Device homeA = device(1L, "10.0.0.10");
        Device homeB = device(2L, "10.0.0.20");
        Device pub = publicDevice(7L, "10.0.0.30");
        Device docker = dockerDevice(8L, "172.18.0.2");
        docker.setOriginHostIp("10.0.0.30");   // origin resolves to the PUBLIC device's IP
        when(deviceRepo.findAll()).thenReturn(List.of(homeA, homeB, pub, docker));

        // Exploitable CVE on the PUBLIC device — would draw EXPLOITABLE_VULN edges from peers.
        NetworkService svc = new NetworkService(10L, 7L, 22, "tcp", "openssh", "8.2", Instant.EPOCH);
        when(serviceRepo.findByDeviceId(7L)).thenReturn(List.of(svc));
        // Vulnerable service on a HOME peer too — were PUBLIC bucketed, the pass
        // would draw pub→homeA, so the outbound direction is constructible-if-broken.
        NetworkService homeSvc = new NetworkService(11L, 1L, 80, "tcp", "nginx", "1.18", Instant.EPOCH);
        when(serviceRepo.findByDeviceId(1L)).thenReturn(List.of(homeSvc));
        Cve cve = new Cve();
        cve.setCveId("CVE-PUBLIC-1");
        cve.setCvssV31Score(new BigDecimal("9.0"));
        cve.setLastModified(Instant.EPOCH);
        cve.setRawJson("{}");
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(cve));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        DeviceVertex vPublic = new DeviceVertex(7L, "10.0.0.30");
        assertThat(g.containsVertex(vPublic))
            .as("PUBLIC device must still appear as a vertex")
            .isTrue();
        assertThat(g.edgesOf(vPublic))
            .as("no edge of ANY type may touch a PUBLIC vertex, in either direction")
            .isEmpty();

        // Surgical isolation: the HOME peers keep their own SAME_SUBNET adjacency.
        DeviceVertex vHomeA = new DeviceVertex(1L, "10.0.0.10");
        DeviceVertex vHomeB = new DeviceVertex(2L, "10.0.0.20");
        assertThat(g.getEdge(vHomeA, vHomeB))
            .as("HOME peers in the shared /24 keep their SAME_SUBNET edge")
            .isNotNull();

        // Sanity: the EXPLOITABLE_VULN machinery actually fired between HOME peers,
        // so the empty edgesOf(vPublic) above is meaningful, not a dead pass.
        assertThat(g.getAllEdges(vHomeB, vHomeA).stream()
            .anyMatch(e -> e.getType() == EdgeType.EXPLOITABLE_VULN))
            .as("sanity: homeB→homeA EXPLOITABLE_VULN edge must form for the vulnerable HOME peer")
            .isTrue();

        // The PUBLIC device has no peers after the bucket guard, so the
        // peers-isEmpty hoist must skip its service fetch entirely — not just
        // produce zero edges from a fetched-and-matched service list.
        verify(serviceRepo, never()).findByDeviceId(7L);
    }

    /**
     * Pins the EXISTING by-construction exclusion of PUBLIC from the GATEWAY_PIVOT pass:
     * a PUBLIC device parked at the configured dockerHostIp is never selected as the
     * local pivot ahead of an eligible HOME device at the same IP, a PUBLIC device whose
     * IP equals a docker member's originHostIp is never selected as a remote pivot, and
     * PUBLIC is never a partition member (membership requires DOCKER_BRIDGE scope).
     *
     * <p>Both partitions deliberately contain a RESOLVABLE HOME pivot so the pass
     * actually emits edges — without one, pivot resolution returns null, no
     * GATEWAY_PIVOT edge can exist for ANY scope, and the no-edges-on-PUBLIC
     * assertions would pass vacuously.
     */
    @Test
    void publicNeverGatewayPivotSource_andNeverMember() {
        // PUBLIC squatting on the configured docker-host IP — not an eligible local
        // pivot. The HOME device at the same IP IS, so the local partition resolves.
        Device publicAtDockerHostIp = publicDevice(7L, "192.168.68.51");
        Device homeAtDockerHostIp = device(5L, "192.168.68.51");
        Device localDocker = dockerDevice(4L, "172.17.0.2");   // originHostIp="local" (entity default)

        // PUBLIC at a remote origin's host IP — not an eligible remote pivot. The HOME
        // device at the same IP IS, so the remote partition resolves too.
        Device publicAtRemoteOrigin = publicDevice(8L, "203.0.113.7");
        Device homeAtRemoteOrigin = device(10L, "203.0.113.7");
        Device remoteDocker = dockerDevice(9L, "172.18.0.2");
        remoteDocker.setOriginHostIp("203.0.113.7");

        when(deviceRepo.findAll()).thenReturn(
            List.of(publicAtDockerHostIp, homeAtDockerHostIp, localDocker,
                publicAtRemoteOrigin, homeAtRemoteOrigin, remoteDocker));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        // Sanity (de-vacuizes the test): both partitions resolved their HOME pivot
        // and emitted GATEWAY_PIVOT edges to their docker members.
        DeviceVertex vHomeLocal = new DeviceVertex(5L, "192.168.68.51");
        DeviceVertex vLocalDocker = new DeviceVertex(4L, "172.17.0.2");
        DeviceVertex vHomeRemote = new DeviceVertex(10L, "203.0.113.7");
        DeviceVertex vRemoteDocker = new DeviceVertex(9L, "172.18.0.2");
        assertThat(g.getEdge(vHomeLocal, vLocalDocker))
            .as("local partition resolves the HOME pivot, not the co-located PUBLIC device")
            .isNotNull();
        assertThat(g.getEdge(vHomeRemote, vRemoteDocker))
            .as("remote partition resolves the HOME pivot, not the co-located PUBLIC device")
            .isNotNull();

        // The actual invariant: with pivots resolving all around, the PUBLIC vertices
        // still touch no GATEWAY_PIVOT edge — neither as pivot nor as member.
        DeviceVertex vPubLocal = new DeviceVertex(7L, "192.168.68.51");
        DeviceVertex vPubRemote = new DeviceVertex(8L, "203.0.113.7");
        assertThat(g.edgesOf(vPubLocal).stream()
            .anyMatch(e -> e.getType() == EdgeType.GATEWAY_PIVOT))
            .as("PUBLIC at the docker-host IP gets no GATEWAY_PIVOT edge in either direction")
            .isFalse();
        assertThat(g.edgesOf(vPubRemote).stream()
            .anyMatch(e -> e.getType() == EdgeType.GATEWAY_PIVOT))
            .as("PUBLIC at the remote origin IP gets no GATEWAY_PIVOT edge in either direction")
            .isFalse();
    }

    /**
     * The realistic v4 co-bucket case the classifier actually produces: two PUBLIC
     * internet endpoints sharing a routable /24 (e.g. two peers in the same hosting
     * provider range). Neither may receive SAME_SUBNET — or, via peer starvation,
     * EXPLOITABLE_VULN — edges, even though one runs a vulnerable service.
     */
    @Test
    void twoPublicDevicesSharingPublicSlash24StayIsolated() {
        Device pubA = publicDevice(1L, "203.0.113.7");
        Device pubB = publicDevice(2L, "203.0.113.9");
        when(deviceRepo.findAll()).thenReturn(List.of(pubA, pubB));

        NetworkService svc = new NetworkService(10L, 1L, 22, "tcp", "openssh", "8.2", Instant.EPOCH);
        when(serviceRepo.findByDeviceId(1L)).thenReturn(List.of(svc));
        Cve cve = new Cve();
        cve.setCveId("CVE-PUBLIC-2");
        cve.setCvssV31Score(new BigDecimal("9.0"));
        cve.setLastModified(Instant.EPOCH);
        cve.setRawJson("{}");
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(cve));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        assertThat(g.vertexSet()).hasSize(2);
        assertThat(g.edgeSet())
            .as("PUBLIC endpoints sharing a routable /24 get no edges of any type")
            .isEmpty();

        // Neither PUBLIC device has peers after the bucket guard, so the
        // peers-isEmpty hoist must skip the service fetch for both — no
        // findByDeviceId call at all.
        verify(serviceRepo, never()).findByDeviceId(anyLong());
    }

    /**
     * IPv6 carve-out from the isolation invariant: DiscoveryScopeClassifier maps every
     * global-unicast v6 address to PUBLIC — including RA/SLAAC-assigned LAN prefixes —
     * so two PUBLIC v6 devices sharing a /64 are very likely genuinely on the same
     * link and MUST keep their SAME_SUBNET adjacency (and the EXPLOITABLE_VULN edges
     * it feeds). Pins the v4-only scoping of the bucket-fill guard.
     */
    @Test
    void publicV6DevicesSharingSlash64KeepSameSubnetEdges() {
        Device pubA = publicDevice(1L, "2a02:8071:1:1::a");
        Device pubB = publicDevice(2L, "2a02:8071:1:1::b");
        when(deviceRepo.findAll()).thenReturn(List.of(pubA, pubB));

        NetworkService svc = new NetworkService(10L, 2L, 22, "tcp", "openssh", "8.2", Instant.EPOCH);
        when(serviceRepo.findByDeviceId(2L)).thenReturn(List.of(svc));
        Cve cve = new Cve();
        cve.setCveId("CVE-V6-1");
        cve.setCvssV31Score(new BigDecimal("9.0"));
        cve.setLastModified(Instant.EPOCH);
        cve.setRawJson("{}");
        when(cveMatcher.findVulnerable(anyString())).thenReturn(List.of(cve));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        DeviceVertex va = new DeviceVertex(1L, "2a02:8071:1:1::a");
        DeviceVertex vb = new DeviceVertex(2L, "2a02:8071:1:1::b");
        AttackEdge ab = g.getEdge(va, vb);
        AttackEdge ba = g.getEdge(vb, va);
        assertThat(ab)
            .as("PUBLIC v6 devices in a shared /64 keep SAME_SUBNET adjacency (SLAAC LAN)")
            .isNotNull();
        assertThat(ba).isNotNull();
        assertThat(ab.getType()).isEqualTo(EdgeType.SAME_SUBNET);
        assertThat(g.getAllEdges(va, vb).stream()
            .anyMatch(e -> e.getType() == EdgeType.EXPLOITABLE_VULN))
            .as("the kept v6 adjacency also feeds EXPLOITABLE_VULN toward the vulnerable peer")
            .isTrue();
    }

    /**
     * Pins the deliberate asymmetry with PUBLIC isolation: a LINK_LOCAL device in a
     * shared /24 DOES get SAME_SUBNET edges. 169.254.0.0/16 adjacency is genuine L2
     * adjacency — link-local peers really can reach each other on the segment — whereas
     * a shared /24 across the public internet is meaningless. Verified against current
     * behavior: the scope-blind subnet bucketing already gives LINK_LOCAL these edges
     * today, and the PUBLIC-isolation change must NOT take them away.
     * (linkLocalStaysIsolated covers LINK_LOCAL's other isolation properties.)
     */
    @Test
    void linkLocalKeepsSameSubnetEdges() {
        Device llA = device(1L, "169.254.73.10");
        llA.setDiscoveryScope(DiscoveryScope.LINK_LOCAL);
        Device llB = device(2L, "169.254.73.152");
        llB.setDiscoveryScope(DiscoveryScope.LINK_LOCAL);
        when(deviceRepo.findAll()).thenReturn(List.of(llA, llB));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        DeviceVertex va = new DeviceVertex(1L, "169.254.73.10");
        DeviceVertex vb = new DeviceVertex(2L, "169.254.73.152");
        AttackEdge ab = g.getEdge(va, vb);
        AttackEdge ba = g.getEdge(vb, va);
        assertThat(ab)
            .as("LINK_LOCAL peers in a shared /24 keep SAME_SUBNET adjacency")
            .isNotNull();
        assertThat(ba).isNotNull();
        assertThat(ab.getType()).isEqualTo(EdgeType.SAME_SUBNET);
    }

    /**
     * A MAC-only placeholder IP ({@code "mac:..."}) is not an IP literal —
     * {@code InetAddress.getByName} would attempt hostname RESOLUTION on the request path.
     * extractSubnetKey must short-circuit to {@code null}, the same bucket as an
     * unparseable IP, without touching the resolver.
     */
    @Test
    void extractSubnetKey_placeholderIp_returnsNullLikeUnparseable() {
        assertThat(GraphBuilder.extractSubnetKey("mac:aa-bb-cc-dd-ee-ff"))
            .as("placeholder IP must bucket exactly like an unparseable IP")
            .isEqualTo(GraphBuilder.extractSubnetKey("not-an-ip%%%"));
        assertThat(GraphBuilder.extractSubnetKey("mac:aa-bb-cc-dd-ee-ff")).isNull();
    }

    /**
     * End-to-end through build(): a placeholder-IP device must not throw and must get no
     * SAME_SUBNET edges — it lands in the skip bucket, exactly like a device whose IP
     * fails to parse.
     */
    @Test
    void build_placeholderIpDevice_noExceptionNoSubnetEdges() {
        Device placeholder = device(1L, "mac:aa-bb-cc-dd-ee-ff");
        Device a = device(2L, "10.0.0.1");
        Device b = device(3L, "10.0.0.2");
        when(deviceRepo.findAll()).thenReturn(List.of(placeholder, a, b));

        Graph<DeviceVertex, AttackEdge> g = builder.build().graph();

        DeviceVertex vPlaceholder = new DeviceVertex(1L, "mac:aa-bb-cc-dd-ee-ff");
        assertThat(g.containsVertex(vPlaceholder)).isTrue();
        assertThat(g.edgesOf(vPlaceholder))
            .as("placeholder-IP device must get no subnet adjacency")
            .isEmpty();
        // Sanity: the real-IP pair still gets SAME_SUBNET edges in the same build.
        assertThat(g.getEdge(new DeviceVertex(2L, "10.0.0.1"), new DeviceVertex(3L, "10.0.0.2")))
            .isNotNull();
    }

    private static org.assertj.core.data.Offset<Double> within(double tolerance) {
        return org.assertj.core.data.Offset.offset(tolerance);
    }
}
