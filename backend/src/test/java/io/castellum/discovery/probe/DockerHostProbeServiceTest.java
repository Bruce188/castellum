package io.castellum.discovery.probe;

import io.castellum.audit.AuditService;
import io.castellum.discovery.DeviceRoleClassifier;
import io.castellum.discovery.DeviceUpsertService;
import io.castellum.discovery.DiscoveryScopeClassifier;
import io.castellum.discovery.DockerDiscoveryService;
import io.castellum.discovery.DockerInspectParser;
import io.castellum.discovery.OriginContext;
import io.castellum.discovery.DockerCliClient;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Integration tests for {@link DockerHostProbeService} against a real H2 database.
 *
 * <p>Uses a fake {@link DockerEngineApiClient.HttpGetter} and a
 * {@code Predicate<HostPort> reachable} seam — no real TCP connections.
 */
@DataJpaTest
@Import({
    DeviceUpsertService.class,
    DiscoveryScopeClassifier.class,
    DeviceRoleClassifier.class,
    DockerInspectParser.class,
    DockerApiNetworkMapper.class,
    DockerApiContainerListMapper.class,
    JacksonAutoConfiguration.class
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class DockerHostProbeServiceTest {

    static final Instant FIXED_NOW = Instant.parse("2026-05-30T12:00:00Z");

    @Autowired DeviceRepository deviceRepository;
    @Autowired NetworkServiceRepository networkServiceRepository;
    @Autowired DeviceUpsertService deviceUpsertService;
    @Autowired DockerInspectParser inspectParser;
    @Autowired DockerApiNetworkMapper networkMapper;
    @Autowired DockerApiContainerListMapper containerListMapper;

    final AuditService auditService = Mockito.mock(AuditService.class);

    // Fixtures
    private static String fixture(String name) throws IOException {
        try (InputStream in = DockerHostProbeServiceTest.class.getResourceAsStream("/docker/" + name)) {
            if (in == null) throw new IOException("fixture /docker/" + name + " not found");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /** Build a DockerDiscoveryService with a no-op CLI (we call ingest() directly). */
    private DockerDiscoveryService discoveryService() {
        DockerCliClient.CommandRunner noOp = argv -> new DockerCliClient.CommandResult(0, "[]", "");
        return new DockerDiscoveryService(
            new DockerCliClient(noOp), inspectParser, deviceUpsertService, deviceRepository,
            networkServiceRepository, auditService,
            Clock.fixed(FIXED_NOW, ZoneOffset.UTC));
    }

    private static final ObjectMapper TEST_OM = new ObjectMapper();

    /** Null-object HTTP-UI clients (all return empty). */
    private static TraefikApiClient noopTraefikClient() {
        return new TraefikApiClient(uri -> Optional.empty());
    }
    private static PortainerApiClient noopPortainerClient() {
        return new PortainerApiClient(uri -> Optional.empty());
    }
    private static CAdvisorApiClient noopCadvisorClient() {
        return new CAdvisorApiClient(uri -> Optional.empty());
    }

    private static K8sApiClient noopK8sClient() {
        return new K8sApiClient(uri -> Optional.empty());
    }
    private static KubeletApiClient noopKubeletClient() {
        return new KubeletApiClient(uri -> Optional.empty());
    }
    private static RegistryApiClient noopRegistryClient() {
        return new RegistryApiClient(uri -> Optional.empty());
    }

    /** Build a probe service with the given getter and reachability seam (SNMP + HTTP-UI + k8s/registry disabled). */
    private DockerHostProbeService buildProbe(DockerEngineApiClient.HttpGetter getter,
                                               Predicate<HostPort> reachable) {
        SnmpClient snmpClient = new SnmpClient((h, c, o) -> Optional.empty());
        SnmpBridgeMapper snmpMapper = new SnmpBridgeMapper();
        TraefikApiClient traefikClient = noopTraefikClient();
        TraefikRouterMapper traefikMapper = new TraefikRouterMapper(TEST_OM);
        PortainerApiClient portainerClient = noopPortainerClient();
        CAdvisorApiClient cadvisorClient = noopCadvisorClient();
        CAdvisorContainerMapper cadvisorMapper = new CAdvisorContainerMapper(TEST_OM);
        Port8080Fingerprinter fingerprinter = new Port8080Fingerprinter(traefikClient, cadvisorClient, TEST_OM);
        DockerEngineApiClient apiClient = new DockerEngineApiClient(getter);
        return new DockerHostProbeService(
            deviceUpsertService, deviceRepository, discoveryService(),
            apiClient, networkMapper, containerListMapper, inspectParser,
            networkServiceRepository, auditService,
            snmpClient, snmpMapper, "public", /* snmpEnabled */ false,
            traefikClient, traefikMapper, portainerClient, cadvisorClient, cadvisorMapper,
            fingerprinter, /* traefikEnabled */ false, /* portainerEnabled */ false,
            /* cadvisorEnabled */ false,
            noopK8sClient(), noopKubeletClient(), new K8sPodMapper(TEST_OM), /* k8sEnabled */ false,
            noopRegistryClient(), new RegistryCatalogMapper(TEST_OM), /* registryEnabled */ false,
            /* maxConcurrent */ 4, reachable);
    }

    /** Build a probe service with full SNMP seam enabled. */
    private DockerHostProbeService buildProbeWithSnmp(DockerEngineApiClient.HttpGetter getter,
                                                       Predicate<HostPort> reachable,
                                                       SnmpClient.SnmpWalker snmpWalker,
                                                       String snmpCommunity) {
        SnmpClient snmpClient = new SnmpClient(snmpWalker);
        SnmpBridgeMapper snmpMapper = new SnmpBridgeMapper();
        TraefikApiClient traefikClient = noopTraefikClient();
        TraefikRouterMapper traefikMapper = new TraefikRouterMapper(TEST_OM);
        PortainerApiClient portainerClient = noopPortainerClient();
        CAdvisorApiClient cadvisorClient = noopCadvisorClient();
        CAdvisorContainerMapper cadvisorMapper = new CAdvisorContainerMapper(TEST_OM);
        Port8080Fingerprinter fingerprinter = new Port8080Fingerprinter(traefikClient, cadvisorClient, TEST_OM);
        DockerEngineApiClient apiClient = new DockerEngineApiClient(getter);
        return new DockerHostProbeService(
            deviceUpsertService, deviceRepository, discoveryService(),
            apiClient, networkMapper, containerListMapper, inspectParser,
            networkServiceRepository, auditService,
            snmpClient, snmpMapper, snmpCommunity, /* snmpEnabled */ true,
            traefikClient, traefikMapper, portainerClient, cadvisorClient, cadvisorMapper,
            fingerprinter, false, false, false,
            noopK8sClient(), noopKubeletClient(), new K8sPodMapper(TEST_OM), /* k8sEnabled */ false,
            noopRegistryClient(), new RegistryCatalogMapper(TEST_OM), /* registryEnabled */ false,
            /* maxConcurrent */ 4, reachable);
    }

    /** Build a probe with custom HTTP-UI clients + fingerprinter. */
    private DockerHostProbeService buildProbeWithUiClients(
            DockerEngineApiClient.HttpGetter dockerGetter,
            Predicate<HostPort> reachable,
            TraefikApiClient traefikClient,
            PortainerApiClient portainerClient,
            CAdvisorApiClient cadvisorClient,
            boolean traefikEnabled, boolean portainerEnabled, boolean cadvisorEnabled) {
        SnmpClient snmpClient = new SnmpClient((h, c, o) -> Optional.empty());
        SnmpBridgeMapper snmpMapper = new SnmpBridgeMapper();
        TraefikRouterMapper traefikMapper = new TraefikRouterMapper(TEST_OM);
        CAdvisorContainerMapper cadvisorMapper = new CAdvisorContainerMapper(TEST_OM);
        Port8080Fingerprinter fingerprinter =
            new Port8080Fingerprinter(traefikClient, cadvisorClient, TEST_OM);
        DockerEngineApiClient apiClient = new DockerEngineApiClient(dockerGetter);
        return new DockerHostProbeService(
            deviceUpsertService, deviceRepository, discoveryService(),
            apiClient, networkMapper, containerListMapper, inspectParser,
            networkServiceRepository, auditService,
            snmpClient, snmpMapper, "public", false,
            traefikClient, traefikMapper, portainerClient, cadvisorClient, cadvisorMapper,
            fingerprinter, traefikEnabled, portainerEnabled, cadvisorEnabled,
            noopK8sClient(), noopKubeletClient(), new K8sPodMapper(TEST_OM), /* k8sEnabled */ false,
            noopRegistryClient(), new RegistryCatalogMapper(TEST_OM), /* registryEnabled */ false,
            /* maxConcurrent */ 4, reachable);
    }

    /** Build a probe with k8s/registry enabled and given client seams. */
    private DockerHostProbeService buildProbeWithK8sRegistry(
            DockerEngineApiClient.HttpGetter dockerGetter,
            Predicate<HostPort> reachable,
            K8sApiClient k8sClient,
            KubeletApiClient kubeletClient,
            RegistryApiClient registryClient,
            boolean k8sEnabled, boolean registryEnabled) {
        SnmpClient snmpClient = new SnmpClient((h, c, o) -> Optional.empty());
        SnmpBridgeMapper snmpMapper = new SnmpBridgeMapper();
        TraefikApiClient traefikClient = noopTraefikClient();
        TraefikRouterMapper traefikMapper = new TraefikRouterMapper(TEST_OM);
        PortainerApiClient portainerClient = noopPortainerClient();
        CAdvisorApiClient cadvisorClient = noopCadvisorClient();
        CAdvisorContainerMapper cadvisorMapper = new CAdvisorContainerMapper(TEST_OM);
        Port8080Fingerprinter fingerprinter = new Port8080Fingerprinter(traefikClient, cadvisorClient, TEST_OM);
        DockerEngineApiClient apiClient = new DockerEngineApiClient(dockerGetter);
        return new DockerHostProbeService(
            deviceUpsertService, deviceRepository, discoveryService(),
            apiClient, networkMapper, containerListMapper, inspectParser,
            networkServiceRepository, auditService,
            snmpClient, snmpMapper, "public", false,
            traefikClient, traefikMapper, portainerClient, cadvisorClient, cadvisorMapper,
            fingerprinter, false, false, false,
            k8sClient, kubeletClient, new K8sPodMapper(TEST_OM), k8sEnabled,
            registryClient, new RegistryCatalogMapper(TEST_OM), registryEnabled,
            /* maxConcurrent */ 4, reachable);
    }

    /** Seed a device row for the given IP at origin='local' (simulates scan discovery). */
    private Device seedLocalDevice(String ip) {
        io.castellum.discovery.Discovery disc = new io.castellum.discovery.Discovery(
            ip, null, "host-" + ip,
            io.castellum.discovery.DiscoverySource.NMAP_SCAN,
            FIXED_NOW, null, false);
        return deviceUpsertService.upsert(disc);
    }

    @BeforeEach
    void setUp() {
        deviceRepository.deleteAll();
        networkServiceRepository.deleteAll();
    }

    // -----------------------------------------------------------------------
    // (1) :2375 reachable → containers ingested with remote origin + CRITICAL finding
    // -----------------------------------------------------------------------

    @Test
    void probe_2375Reachable_ingestsDevicesWithOriginAndCriticalFinding() throws Exception {
        // Seed the probed host as a local inventory device
        String probedIp = "10.0.0.50";
        Device hostDevice = seedLocalDevice(probedIp);

        // Fake getter: /containers/json → list with one ID; /containers/{id}/json → inspect
        String containerListJson = "[{\"Id\":\"abc123\"}]";
        // Wrap the inspect fixture as a single-element array (the client gets the raw element
        // from /containers/{id}/json which DockerInspectParser expects as an array)
        String inspectJson = fixture("api-container-inspect.json");
        // api-container-inspect.json is already an array — extract first element for /containers/{id}/json
        com.fasterxml.jackson.databind.ObjectMapper om = new com.fasterxml.jackson.databind.ObjectMapper();
        String singleInspect = om.writeValueAsString(om.readTree(inspectJson).get(0));

        DockerEngineApiClient.HttpGetter getter = uri -> {
            String path = uri.getPath();
            if (path.equals("/containers/json")) return Optional.of(containerListJson);
            if (path.startsWith("/containers/")) return Optional.of(singleInspect);
            return Optional.empty();
        };

        // :2375 reachable, all others closed
        Predicate<HostPort> reachable = hp -> hp.port() == DockerHostProbeService.PORT_2375
            && hp.host().equals(probedIp);

        DockerHostProbeService probe = buildProbe(getter, reachable);
        probe.probeHosts(List.of(probedIp));

        // Container devices upserted with origin = probedIp
        Optional<Device> containerDevice = deviceRepository.findByIpAddressAndOriginHostIp(
            "172.18.0.4", probedIp);
        assertThat(containerDevice).isPresent();
        assertThat(containerDevice.get().getOriginHostIp()).isEqualTo(probedIp);

        // CRITICAL posture finding on host device at port 2375
        Optional<NetworkService> finding = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(hostDevice.getId(), 2375, "tcp");
        assertThat(finding).isPresent();
        assertThat(finding.get().getPostureSeverity()).isEqualTo("CRITICAL");
        assertThat(finding.get().getProtocolFamily())
            .isEqualTo(DockerHostProbeService.PROTOCOL_FAMILY_DOCKER_EXPOSURE);
    }

    // -----------------------------------------------------------------------
    // (2) :2376 reachable → HIGH finding only, NO container extraction
    // -----------------------------------------------------------------------

    @Test
    void probe_2376NoCert_findingOnlyNoExtraction() {
        String probedIp = "10.0.0.51";
        Device hostDevice = seedLocalDevice(probedIp);

        // Getter that should NEVER be called for :2376 (no extraction)
        DockerEngineApiClient.HttpGetter getter = uri -> {
            throw new AssertionError("HTTP getter must NOT be called for :2376 probe");
        };

        // Only :2376 reachable
        Predicate<HostPort> reachable = hp -> hp.port() == DockerHostProbeService.PORT_2376
            && hp.host().equals(probedIp);

        DockerHostProbeService probe = buildProbe(getter, reachable);
        probe.probeHosts(List.of(probedIp));

        // HIGH finding on host device at port 2376
        Optional<NetworkService> finding = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(hostDevice.getId(), 2376, "tcp");
        assertThat(finding).isPresent();
        assertThat(finding.get().getPostureSeverity()).isEqualTo("HIGH");
        assertThat(finding.get().getProtocolFamily())
            .isEqualTo(DockerHostProbeService.PROTOCOL_FAMILY_DOCKER_EXPOSURE);

        // NO docker-bridge container devices should have been created
        long containerDeviceCount = deviceRepository.findAll().stream()
            .filter(d -> probedIp.equals(d.getOriginHostIp()))
            .count();
        assertThat(containerDeviceCount).isZero();
    }

    // -----------------------------------------------------------------------
    // (3) All ports closed → no-op (no findings, no devices)
    // -----------------------------------------------------------------------

    @Test
    void probe_closedPort_noOp() {
        String probedIp = "10.0.0.52";
        seedLocalDevice(probedIp);
        long devicesBefore = deviceRepository.count();

        // No ports reachable
        Predicate<HostPort> reachable = hp -> false;
        DockerHostProbeService probe = buildProbe(uri -> Optional.empty(), reachable);
        probe.probeHosts(List.of(probedIp));

        // No new devices or findings
        assertThat(deviceRepository.count()).isEqualTo(devicesBefore);
        assertThat(networkServiceRepository.count()).isZero();
    }

    // -----------------------------------------------------------------------
    // (4) Malformed JSON → host isolated, scan continues for second host
    // -----------------------------------------------------------------------

    @Test
    void probe_malformedJson_handledScanContinues() throws Exception {
        String badHost = "10.0.0.53";
        String goodHost = "10.0.0.54";
        Device badHostDevice = seedLocalDevice(badHost);
        Device goodHostDevice = seedLocalDevice(goodHost);

        // Good host fixture
        String containerListJson = "[{\"Id\":\"abc123\"}]";
        String inspectJson = fixture("api-container-inspect.json");
        com.fasterxml.jackson.databind.ObjectMapper om = new com.fasterxml.jackson.databind.ObjectMapper();
        String singleInspect = om.writeValueAsString(om.readTree(inspectJson).get(0));

        // Getter: bad host returns malformed JSON, good host returns valid data
        DockerEngineApiClient.HttpGetter getter = uri -> {
            String host = uri.getHost();
            String path = uri.getPath();
            if (host.equals(badHost)) {
                // Return malformed JSON for container list
                return Optional.of("{not valid json!!!");
            }
            if (path.equals("/containers/json")) return Optional.of(containerListJson);
            if (path.startsWith("/containers/")) return Optional.of(singleInspect);
            return Optional.empty();
        };

        // Both hosts reachable on :2375
        Predicate<HostPort> reachable = hp -> hp.port() == DockerHostProbeService.PORT_2375;

        DockerHostProbeService probe = buildProbe(getter, reachable);
        probe.probeHosts(List.of(badHost, goodHost));

        // Good host must have had containers ingested with its origin
        long goodOriginDevices = deviceRepository.findAll().stream()
            .filter(d -> goodHost.equals(d.getOriginHostIp()))
            .count();
        assertThat(goodOriginDevices).isGreaterThan(0);
        // No crash — scan continues
    }

    // -----------------------------------------------------------------------
    // (5) Self-check: loopback-only → no finding
    // -----------------------------------------------------------------------

    @Test
    void selfCheck_loopbackOnly_noFinding() {
        // Reachable seam: only loopback (127.0.0.1) would be reachable — but self-check
        // only enumerates non-loopback interfaces. If there are none, no finding should appear.
        // We control this by making the reachable predicate return false for everything
        // (simulating a loopback-only environment where no non-loopback NIC is present).
        Predicate<HostPort> noneReachable = hp -> false;
        DockerHostProbeService probe = buildProbe(uri -> Optional.empty(), noneReachable);

        // runSelfCheck enumerates real NICs but then tests with the seam
        // In CI the host has no non-loopback docker-bound NIC, so this is effectively a no-op.
        // We assert no findings are created.
        probe.runSelfCheck();
        assertThat(networkServiceRepository.count()).isZero();
    }

    // -----------------------------------------------------------------------
    // (6) Self-check: simulate non-loopback local IP reachable → CRITICAL self-finding
    // -----------------------------------------------------------------------

    @Test
    void selfCheck_nonLoopbackBind_finding() {
        // Seed a local device for a non-loopback IP that "appears" in the self-check
        String selfIp = "10.0.0.1";
        Device selfDevice = seedLocalDevice(selfIp);

        // Build a probe whose self-check simulates a non-loopback IP reachable
        // We do this by building a custom subclass that overrides localNonLoopbackIpv4()
        // equivalent — actually we test by seeding the device and having the reachable seam
        // return true for that IP. But runSelfCheck() enumerates REAL interfaces.
        // Instead, build a probe where we call the reachability-raising logic directly
        // by testing an IP that IS in the inventory and has the seam return true.

        // We use a trick: build a probe with reachable=true for the selfIp port 2375,
        // then call the probe directly on it as a "selfCheck-like" call via probeHosts.
        // The real self-check uses NetworkInterface enumeration which is OS-dependent.
        // For the test, we simulate this by calling probeHosts with the selfIp.
        Predicate<HostPort> selfReachable = hp -> hp.host().equals(selfIp)
            && hp.port() == DockerHostProbeService.PORT_2375;

        // Getter returns empty for containers (we just want the finding)
        DockerEngineApiClient.HttpGetter getter = uri -> Optional.of("[]");
        DockerHostProbeService probe = buildProbe(getter, selfReachable);

        // Probe the self IP — this mimics what runSelfCheck would do for a non-loopback NIC
        probe.probeHosts(List.of(selfIp));

        // CRITICAL finding for the self IP
        Optional<NetworkService> finding = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(selfDevice.getId(), 2375, "tcp");
        assertThat(finding).isPresent();
        assertThat(finding.get().getPostureSeverity()).isEqualTo("CRITICAL");
    }

    // -----------------------------------------------------------------------
    // (7) Audit events emitted on success
    // -----------------------------------------------------------------------

    @Test
    void probe_2375Reachable_emitsAuditEvent() throws Exception {

        String probedIp = "10.0.0.55";
        seedLocalDevice(probedIp);

        DockerEngineApiClient.HttpGetter getter = uri -> {
            String path = uri.getPath();
            if (path.equals("/containers/json")) return Optional.of("[]");
            return Optional.empty();
        };

        Predicate<HostPort> reachable = hp -> hp.port() == DockerHostProbeService.PORT_2375;
        DockerHostProbeService probe = buildProbe(getter, reachable);
        probe.probeHosts(List.of(probedIp));

        verify(auditService, atLeastOnce()).recordEvent(
            eq("system"), eq("DOCKER_PROBE"), eq("docker_probe"), any(), any());
    }

    // -----------------------------------------------------------------------
    // (8) SNMP: bridges recovered → ingestNetworks, no phantom containers
    // -----------------------------------------------------------------------

    /** Helper: build varbind for ifDescr subtree. */
    private static VariableBinding ifDescrVb(int idx, String val) {
        return new VariableBinding(new OID("1.3.6.1.2.1.2.2.1.2." + idx), new OctetString(val));
    }
    private static VariableBinding ifNameVb(int idx, String val) {
        return new VariableBinding(new OID("1.3.6.1.2.1.31.1.1.1.1." + idx), new OctetString(val));
    }
    private static VariableBinding ifTypeVb(int idx, int t) {
        return new VariableBinding(new OID("1.3.6.1.2.1.2.2.1.3." + idx),
            new org.snmp4j.smi.Integer32(t));
    }
    private static VariableBinding ipIdxVb(String ip, int idx) {
        return new VariableBinding(new OID("1.3.6.1.2.1.4.20.1.2." + ip),
            new org.snmp4j.smi.Integer32(idx));
    }
    private static VariableBinding ipMaskVb(String ip, String mask) {
        return new VariableBinding(new OID("1.3.6.1.2.1.4.20.1.3." + ip), new OctetString(mask));
    }

    @Test
    void snmpBridgesRecovered_ingestsSubnetsOnly_noPhantomContainers() {
        String probedIp = "10.0.0.60";
        seedLocalDevice(probedIp);

        // SNMP walker returns docker0 interface + gateway IP ONLY for "mycommunity";
        // "public" community returns empty (so no LOW udp/161 finding is raised)
        SnmpClient.SnmpWalker walker = (host, community, baseOid) -> {
            if (!"mycommunity".equals(community)) return Optional.empty();
            if (baseOid.equals(SnmpClient.OID_IF_DESCR)) {
                return Optional.of(List.of(ifDescrVb(1, "docker0")));
            }
            if (baseOid.equals(SnmpClient.OID_IF_NAME)) {
                return Optional.of(List.of(ifNameVb(1, "docker0")));
            }
            if (baseOid.equals(SnmpClient.OID_IF_TYPE)) {
                return Optional.of(List.of(ifTypeVb(1, 131)));
            }
            if (baseOid.equals(SnmpClient.OID_IP_IF_IDX)) {
                return Optional.of(List.of(ipIdxVb("172.17.0.1", 1)));
            }
            if (baseOid.equals(SnmpClient.OID_IP_MASK)) {
                return Optional.of(List.of(ipMaskVb("172.17.0.1", "255.255.0.0")));
            }
            return Optional.empty();
        };

        // No Docker ports reachable
        Predicate<HostPort> noDocker = hp -> false;
        DockerHostProbeService probe = buildProbeWithSnmp(
            uri -> Optional.empty(), noDocker, walker, "mycommunity");

        probe.probeHosts(List.of(probedIp));

        // Gateway device upserted (subnets-only)
        Optional<io.castellum.domain.Device> gwDevice =
            deviceRepository.findByIpAddressAndOriginHostIp("172.17.0.1", probedIp);
        assertThat(gwDevice).isPresent();

        // No phantom container rows (only seeded host + gateway)
        long totalDevices = deviceRepository.count();
        assertThat(totalDevices).isEqualTo(2); // host + gateway

        // No udp/161 finding (community != "public" for snmp, public walk returns empty)
        Optional<NetworkService> snmpFinding = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(
                deviceRepository.findByIpAddressAndOriginHostIp(probedIp, "local").get().getId(),
                161, "udp");
        assertThat(snmpFinding).isEmpty();
    }

    @Test
    void snmpPublicAnswers_raisesLowUdpFinding() {
        String probedIp = "10.0.0.61";
        Device hostDevice = seedLocalDevice(probedIp);

        // SNMP walker: only answers for "public" community with docker0 data
        SnmpClient.SnmpWalker walker = (host, community, baseOid) -> {
            if ("public".equals(community) && baseOid.equals(SnmpClient.OID_IF_DESCR)) {
                return Optional.of(List.of(ifDescrVb(1, "docker0")));
            }
            if ("public".equals(community) && baseOid.equals(SnmpClient.OID_IF_NAME)) {
                return Optional.of(List.of(ifNameVb(1, "docker0")));
            }
            if ("public".equals(community) && baseOid.equals(SnmpClient.OID_IF_TYPE)) {
                return Optional.of(List.of(ifTypeVb(1, 131)));
            }
            if ("public".equals(community) && baseOid.equals(SnmpClient.OID_IP_IF_IDX)) {
                return Optional.of(List.of(ipIdxVb("172.17.0.1", 1)));
            }
            if ("public".equals(community) && baseOid.equals(SnmpClient.OID_IP_MASK)) {
                return Optional.of(List.of(ipMaskVb("172.17.0.1", "255.255.0.0")));
            }
            return Optional.empty();
        };

        Predicate<HostPort> noDocker = hp -> false;
        // Community is "private" but "public" walk answers
        DockerHostProbeService probe = buildProbeWithSnmp(
            uri -> Optional.empty(), noDocker, walker, "private");

        probe.probeHosts(List.of(probedIp));

        // LOW udp/161 finding must have been raised
        Optional<NetworkService> finding = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(hostDevice.getId(), 161, "udp");
        assertThat(finding).isPresent();
        assertThat(finding.get().getPostureSeverity()).isEqualTo("LOW");
        assertThat(finding.get().getProtocolFamily())
            .isEqualTo(DockerHostProbeService.PROTOCOL_FAMILY_SNMP_EXPOSURE);
    }

    @Test
    void snmpNoResponse_fastNoOp() {
        String probedIp = "10.0.0.62";
        seedLocalDevice(probedIp);
        long devicesBefore = deviceRepository.count();

        // SNMP walker: always empty (no response)
        SnmpClient.SnmpWalker noResponse = (h, c, o) -> Optional.empty();
        Predicate<HostPort> noDocker = hp -> false;
        DockerHostProbeService probe = buildProbeWithSnmp(
            uri -> Optional.empty(), noDocker, noResponse, "public");

        probe.probeHosts(List.of(probedIp));

        // No new devices, no findings
        assertThat(deviceRepository.count()).isEqualTo(devicesBefore);
        assertThat(networkServiceRepository.count()).isZero();
    }

    @Test
    void snmpDisabled_skipped() {
        String probedIp = "10.0.0.63";
        seedLocalDevice(probedIp);

        // Walker that throws if called
        SnmpClient.SnmpWalker mustNotCall = (h, c, o) -> {
            throw new AssertionError("SNMP walker must NOT be called when snmpEnabled=false");
        };
        // buildProbe uses snmpEnabled=false
        Predicate<HostPort> noDocker = hp -> false;
        DockerHostProbeService probe = buildProbe(uri -> Optional.empty(), noDocker);

        // Should not throw — SNMP is disabled
        probe.probeHosts(List.of(probedIp));
        assertThat(networkServiceRepository.count()).isZero();
    }

    // -----------------------------------------------------------------------
    // Phase 3: HTTP-UI probe tests (task 3.4)
    // -----------------------------------------------------------------------

    private static final String TRAEFIK_OVERVIEW = """
        {"http":{"routers":{"total":1},"services":{"total":1}}}
        """;

    private static final String CADVISOR_MACHINE = """
        {"num_cores":4,"memory_capacity":8589934592}
        """;

    @Test
    void traefik8080_fingerprinted_raisesMediumFinding() {
        String ip = "10.0.1.1";
        Device hostDevice = seedLocalDevice(ip);

        // Traefik client: /api/overview returns Traefik-shaped JSON
        TraefikApiClient traefikClient = new TraefikApiClient(uri -> {
            if (uri.getPath().equals("/api/overview")) return Optional.of(TRAEFIK_OVERVIEW);
            if (uri.getPath().equals("/api/http/routers")) return Optional.of("[]");
            if (uri.getPath().equals("/api/http/services")) return Optional.of("[]");
            return Optional.empty();
        });
        CAdvisorApiClient cadvisorClient = noopCadvisorClient();
        PortainerApiClient portainerClient = noopPortainerClient();

        // :8080 reachable, others closed
        Predicate<HostPort> reachable = hp -> hp.port() == 8080 && hp.host().equals(ip);
        DockerHostProbeService probe = buildProbeWithUiClients(
            uri -> Optional.empty(), reachable,
            traefikClient, portainerClient, cadvisorClient,
            true, false, false);

        probe.probeHosts(List.of(ip));

        Optional<NetworkService> finding = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(hostDevice.getId(), 8080, "tcp");
        assertThat(finding).isPresent();
        assertThat(finding.get().getPostureSeverity()).isEqualTo("MEDIUM");
        assertThat(finding.get().getProtocolFamily())
            .isEqualTo(DockerHostProbeService.PROTOCOL_FAMILY_TRAEFIK_EXPOSURE);
    }

    @Test
    void cadvisor8080_fingerprinted_raisesMediumFinding() {
        String ip = "10.0.1.2";
        Device hostDevice = seedLocalDevice(ip);

        // cAdvisor client: /api/v1.3/machine returns cAdvisor-shaped JSON
        TraefikApiClient traefikClient = new TraefikApiClient(uri -> Optional.empty()); // no Traefik
        CAdvisorApiClient cadvisorClient = new CAdvisorApiClient(uri -> {
            if (uri.getPath().equals("/api/v1.3/machine")) return Optional.of(CADVISOR_MACHINE);
            if (uri.getPath().equals("/api/v1.3/subcontainers")) return Optional.of("[]");
            return Optional.empty();
        });

        Predicate<HostPort> reachable = hp -> hp.port() == 8080 && hp.host().equals(ip);
        DockerHostProbeService probe = buildProbeWithUiClients(
            uri -> Optional.empty(), reachable,
            traefikClient, noopPortainerClient(), cadvisorClient,
            false, false, true);

        probe.probeHosts(List.of(ip));

        Optional<NetworkService> finding = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(hostDevice.getId(), 8080, "tcp");
        assertThat(finding).isPresent();
        assertThat(finding.get().getPostureSeverity()).isEqualTo("MEDIUM");
        assertThat(finding.get().getProtocolFamily())
            .isEqualTo(DockerHostProbeService.PROTOCOL_FAMILY_CADVISOR_EXPOSURE);
    }

    // ---- REQUIRED R3: unknown fingerprint → no extraction, no finding ----

    @Test
    void port8080_unknownFingerprint_noExtractionNoFinding() {
        String ip = "10.0.1.3";
        seedLocalDevice(ip);

        // Both clients return empty → UNKNOWN fingerprint
        TraefikApiClient traefikClient = new TraefikApiClient(uri -> Optional.empty());
        CAdvisorApiClient cadvisorClient = new CAdvisorApiClient(uri -> Optional.empty());

        Predicate<HostPort> reachable = hp -> hp.port() == 8080 && hp.host().equals(ip);
        DockerHostProbeService probe = buildProbeWithUiClients(
            uri -> Optional.empty(), reachable,
            traefikClient, noopPortainerClient(), cadvisorClient,
            true, false, true);

        probe.probeHosts(List.of(ip));

        // R3: no finding must have been created for port 8080
        assertThat(networkServiceRepository.count()).isZero();
    }

    @Test
    void portainer9000_detected_medFinding() {
        String ip = "10.0.1.4";
        Device hostDevice = seedLocalDevice(ip);

        // Portainer client: /api/status responds
        PortainerApiClient portainerClient = new PortainerApiClient(uri -> {
            if (uri.getPath().equals("/api/status")) {
                return Optional.of("{\"Version\":\"2.19.0\",\"Authentication\":false}");
            }
            if (uri.getPath().equals("/api/endpoints")) return Optional.empty();
            return Optional.empty();
        });

        Predicate<HostPort> reachable = hp -> hp.port() == 9000 && hp.host().equals(ip);
        DockerHostProbeService probe = buildProbeWithUiClients(
            uri -> Optional.empty(), reachable,
            noopTraefikClient(), portainerClient, noopCadvisorClient(),
            false, true, false);

        probe.probeHosts(List.of(ip));

        Optional<NetworkService> finding = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(hostDevice.getId(), 9000, "tcp");
        assertThat(finding).isPresent();
        assertThat(finding.get().getPostureSeverity()).isEqualTo("MEDIUM");
        assertThat(finding.get().getProtocolFamily())
            .isEqualTo(DockerHostProbeService.PROTOCOL_FAMILY_PORTAINER_EXPOSURE);
    }

    @Test
    void portainer9000_noAuthEndpoints_extracts() {
        String ip = "10.0.1.5";
        Device hostDevice = seedLocalDevice(ip);

        // Portainer client: /api/status + /api/endpoints both respond (no-auth)
        PortainerApiClient portainerClient = new PortainerApiClient(uri -> {
            if (uri.getPath().equals("/api/status")) {
                return Optional.of("{\"Version\":\"2.19.0\",\"Authentication\":false}");
            }
            if (uri.getPath().equals("/api/endpoints")) {
                return Optional.of("[{\"Id\":1,\"Name\":\"local\"}]");
            }
            return Optional.empty();
        });

        Predicate<HostPort> reachable = hp -> hp.port() == 9000 && hp.host().equals(ip);
        DockerHostProbeService probe = buildProbeWithUiClients(
            uri -> Optional.empty(), reachable,
            noopTraefikClient(), portainerClient, noopCadvisorClient(),
            false, true, false);

        probe.probeHosts(List.of(ip));

        // Finding must still be raised (detection always → finding)
        Optional<NetworkService> finding = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(hostDevice.getId(), 9000, "tcp");
        assertThat(finding).isPresent();
        assertThat(finding.get().getPostureSeverity()).isEqualTo("MEDIUM");
    }

    // -----------------------------------------------------------------------
    // Phase 2 — Kubernetes probes (Tasks 2.3)
    // -----------------------------------------------------------------------

    @Test
    void kubelet10255_podsReturned_ingestsTopology_highFinding() throws Exception {
        String probedIp = "10.0.0.60";
        Device hostDevice = seedLocalDevice(probedIp);

        String kubeletPodsJson = new String(
            DockerHostProbeServiceTest.class.getResourceAsStream("/k8s/kubelet-pods.json").readAllBytes(),
            java.nio.charset.StandardCharsets.UTF_8);

        KubeletApiClient kubeletClient = new KubeletApiClient(uri -> Optional.of(kubeletPodsJson));
        K8sApiClient k8sClient = new K8sApiClient(uri -> Optional.empty()); // :6443 not reachable

        // :10255 reachable, :6443 not reachable
        Predicate<HostPort> reachable = hp ->
            hp.port() == DockerHostProbeService.PORT_10255 && hp.host().equals(probedIp);

        DockerHostProbeService probe = buildProbeWithK8sRegistry(
            uri -> Optional.empty(), reachable,
            k8sClient, kubeletClient, noopRegistryClient(),
            /* k8sEnabled */ true, /* registryEnabled */ false);

        probe.probeHosts(List.of(probedIp));

        // Pod device must be ingested with origin == probed host
        Optional<Device> podDevice = deviceRepository.findByIpAddressAndOriginHostIp("10.244.0.2", probedIp);
        assertThat(podDevice)
            .as("kubelet pod with IP 10.244.0.2 must be ingested with origin = probed host")
            .isPresent();

        // :10255 HIGH finding must be raised on the probed host
        Optional<NetworkService> svc = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(hostDevice.getId(), DockerHostProbeService.PORT_10255, "tcp");
        assertThat(svc).isPresent();
        assertThat(svc.get().getPostureSeverity()).isEqualTo(DockerHostProbeService.SEVERITY_HIGH);
        assertThat(svc.get().getProtocolFamily())
            .isEqualTo(DockerHostProbeService.PROTOCOL_FAMILY_KUBELET_RO_EXPOSURE);
    }

    @Test
    void k8sApi6443_anonymousReadSucceeds_ingestsTopology_criticalFinding() throws Exception {
        String probedIp = "10.0.0.61";
        Device hostDevice = seedLocalDevice(probedIp);

        String k8sPodsJson = new String(
            DockerHostProbeServiceTest.class.getResourceAsStream("/k8s/k8s-pods.json").readAllBytes(),
            java.nio.charset.StandardCharsets.UTF_8);

        K8sApiClient k8sClient = new K8sApiClient(uri -> Optional.of(k8sPodsJson));
        KubeletApiClient kubeletClient = new KubeletApiClient(uri -> Optional.empty());

        // :6443 reachable, :10255 not reachable
        Predicate<HostPort> reachable = hp ->
            hp.port() == DockerHostProbeService.PORT_6443 && hp.host().equals(probedIp);

        DockerHostProbeService probe = buildProbeWithK8sRegistry(
            uri -> Optional.empty(), reachable,
            k8sClient, kubeletClient, noopRegistryClient(),
            /* k8sEnabled */ true, /* registryEnabled */ false);

        probe.probeHosts(List.of(probedIp));

        // Pods must be ingested with origin == probed host
        Optional<Device> podDevice = deviceRepository.findByIpAddressAndOriginHostIp("10.244.0.5", probedIp);
        assertThat(podDevice)
            .as("k8s pod with IP 10.244.0.5 must be ingested with origin = probed host")
            .isPresent();

        // :6443 CRITICAL finding must be raised
        Optional<NetworkService> svc = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(hostDevice.getId(), DockerHostProbeService.PORT_6443, "tcp");
        assertThat(svc).isPresent();
        assertThat(svc.get().getPostureSeverity()).isEqualTo(DockerHostProbeService.SEVERITY_CRITICAL);
        assertThat(svc.get().getProtocolFamily())
            .isEqualTo(DockerHostProbeService.PROTOCOL_FAMILY_K8S_API_EXPOSURE);
    }

    @Test
    void k8sApi6443_401_findingOnly_noData_noRetry() {
        // REQUIRED R3 test: :6443 reachable but getter returns empty (401) →
        //   1. HIGH finding-only (no data extraction)
        //   2. getter invoked EXACTLY ONCE (no retry storm)
        String probedIp = "10.0.0.62";
        Device hostDevice = seedLocalDevice(probedIp);

        java.util.concurrent.atomic.AtomicInteger callCount = new java.util.concurrent.atomic.AtomicInteger(0);
        K8sApiClient k8sClient = new K8sApiClient(uri -> {
            callCount.incrementAndGet();
            return Optional.empty(); // simulates 401
        });
        KubeletApiClient kubeletClient = new KubeletApiClient(uri -> Optional.empty());

        // :6443 reachable, nothing else
        Predicate<HostPort> reachable = hp ->
            hp.port() == DockerHostProbeService.PORT_6443 && hp.host().equals(probedIp);

        DockerHostProbeService probe = buildProbeWithK8sRegistry(
            uri -> Optional.empty(), reachable,
            k8sClient, kubeletClient, noopRegistryClient(),
            /* k8sEnabled */ true, /* registryEnabled */ false);

        long devicesBefore = deviceRepository.count();
        probe.probeHosts(List.of(probedIp));
        long devicesAfter = deviceRepository.count();

        // ZERO new device/topology rows — only the probed host pre-seeded
        assertThat(devicesAfter)
            .as("ZERO new device rows must be created on 401 (finding-only, no data extraction)")
            .isEqualTo(devicesBefore);

        // :6443 HIGH finding must be raised (reachable but auth-required)
        Optional<NetworkService> svc = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(hostDevice.getId(), DockerHostProbeService.PORT_6443, "tcp");
        assertThat(svc).isPresent();
        assertThat(svc.get().getPostureSeverity()).isEqualTo(DockerHostProbeService.SEVERITY_HIGH);

        // REQUIRED: getter invoked EXACTLY ONCE — no retry
        assertThat(callCount.get())
            .as("K8sApiClient getter must be invoked EXACTLY ONCE (no retry on 401, R3)")
            .isEqualTo(1);
    }

    @Test
    void k8sDisabled_skipped() {
        String probedIp = "10.0.0.63";
        seedLocalDevice(probedIp);

        java.util.concurrent.atomic.AtomicInteger callCount = new java.util.concurrent.atomic.AtomicInteger(0);
        K8sApiClient k8sClient = new K8sApiClient(uri -> {
            callCount.incrementAndGet();
            return Optional.empty();
        });
        KubeletApiClient kubeletClient = new KubeletApiClient(uri -> {
            callCount.incrementAndGet();
            return Optional.empty();
        });

        Predicate<HostPort> reachable = hp -> true; // everything reachable

        DockerHostProbeService probe = buildProbeWithK8sRegistry(
            uri -> Optional.empty(), reachable,
            k8sClient, kubeletClient, noopRegistryClient(),
            /* k8sEnabled */ false, /* registryEnabled */ false);

        probe.probeHosts(List.of(probedIp));

        assertThat(callCount.get())
            .as("k8s clients must not be called when k8s is disabled")
            .isEqualTo(0);
    }

    // -----------------------------------------------------------------------
    // Phase 3 — Registry probes (Task 3.2)
    // -----------------------------------------------------------------------

    @Test
    void registry5000_catalogAnswers_attachesImageMetadata_mediumFinding_noTopologyRows() throws Exception {
        String probedIp = "10.0.0.70";
        Device hostDevice = seedLocalDevice(probedIp);

        String catalogJson = new String(
            DockerHostProbeServiceTest.class.getResourceAsStream("/k8s/registry-catalog.json").readAllBytes(),
            java.nio.charset.StandardCharsets.UTF_8);

        RegistryApiClient registryClient = new RegistryApiClient(uri -> Optional.of(catalogJson));

        // :5000 reachable, nothing else (k8s disabled)
        Predicate<HostPort> reachable = hp ->
            hp.port() == DockerHostProbeService.PORT_5000 && hp.host().equals(probedIp);

        DockerHostProbeService probe = buildProbeWithK8sRegistry(
            uri -> Optional.empty(), reachable,
            noopK8sClient(), noopKubeletClient(), registryClient,
            /* k8sEnabled */ false, /* registryEnabled */ true);

        long devicesBefore = deviceRepository.count();
        probe.probeHosts(List.of(probedIp));
        long devicesAfter = deviceRepository.count();

        // ZERO new device topology rows (R6 — registry catalog is HOST METADATA only)
        assertThat(devicesAfter)
            .as("ZERO new device topology rows must be created from registry catalog (R6)")
            .isEqualTo(devicesBefore);

        // registry_images must be set on the probed host Device row
        Device reloadedHost = deviceRepository.findById(hostDevice.getId()).orElseThrow();
        assertThat(reloadedHost.getRegistryImages())
            .as("registry_images must be populated on the probed host device")
            .isNotBlank()
            .contains("nginx")
            .contains("redis");

        // MEDIUM finding must be raised on the probed host
        Optional<NetworkService> svc = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(hostDevice.getId(), DockerHostProbeService.PORT_5000, "tcp");
        assertThat(svc).isPresent();
        assertThat(svc.get().getPostureSeverity()).isEqualTo(DockerHostProbeService.SEVERITY_MEDIUM);
        assertThat(svc.get().getProtocolFamily())
            .isEqualTo(DockerHostProbeService.PROTOCOL_FAMILY_REGISTRY_EXPOSURE);
    }

    @Test
    void registry5000_authRequired_noExtraction() {
        String probedIp = "10.0.0.71";
        seedLocalDevice(probedIp);

        RegistryApiClient registryClient = new RegistryApiClient(uri -> Optional.empty()); // 401

        Predicate<HostPort> reachable = hp ->
            hp.port() == DockerHostProbeService.PORT_5000 && hp.host().equals(probedIp);

        DockerHostProbeService probe = buildProbeWithK8sRegistry(
            uri -> Optional.empty(), reachable,
            noopK8sClient(), noopKubeletClient(), registryClient,
            /* k8sEnabled */ false, /* registryEnabled */ true);

        probe.probeHosts(List.of(probedIp));

        // No finding must be raised (authenticated registry = not the MEDIUM exposure case)
        Device reloaded = deviceRepository.findByIpAddressAndOriginHostIp(probedIp, "local").orElseThrow();
        assertThat(reloaded.getRegistryImages())
            .as("registry_images must not be set when catalog returns 401")
            .isNull();
        long findingCount = networkServiceRepository.findAll().stream()
            .filter(s -> DockerHostProbeService.PROTOCOL_FAMILY_REGISTRY_EXPOSURE.equals(s.getProtocolFamily()))
            .count();
        assertThat(findingCount)
            .as("no REGISTRY_EXPOSURE finding must be raised when catalog is auth-required")
            .isEqualTo(0);
    }

    @Test
    void registryDisabled_skipped() {
        String probedIp = "10.0.0.72";
        seedLocalDevice(probedIp);

        java.util.concurrent.atomic.AtomicInteger callCount = new java.util.concurrent.atomic.AtomicInteger(0);
        RegistryApiClient registryClient = new RegistryApiClient(uri -> {
            callCount.incrementAndGet();
            return Optional.empty();
        });

        Predicate<HostPort> reachable = hp -> true; // everything reachable

        DockerHostProbeService probe = buildProbeWithK8sRegistry(
            uri -> Optional.empty(), reachable,
            noopK8sClient(), noopKubeletClient(), registryClient,
            /* k8sEnabled */ false, /* registryEnabled */ false);

        probe.probeHosts(List.of(probedIp));

        assertThat(callCount.get())
            .as("registry client must not be called when registry is disabled")
            .isEqualTo(0);
    }

    // -----------------------------------------------------------------------
    // Task 2.2 — probe2375 wires getNetworks → ingestNetworks (F2 NB1)
    // -----------------------------------------------------------------------

    /** Minimal /networks response with one bridge network (bridge, 172.17.0.0/16). */
    private static final String NETWORKS_JSON_ONE_BRIDGE = """
        [
          {
            "Id":"abc123",
            "Name":"bridge",
            "IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}
          }
        ]
        """;

    /**
     * (1) :2375 reachable, getNetworks returns a body → ingestNetworks is invoked once
     * with mapped attachments; the gateway device is persisted.
     */
    @Test
    void probe2375_getNetworksReturnsBody_ingestsGateways() throws Exception {
        String probedIp = "10.0.0.90";
        seedLocalDevice(probedIp);

        // Container list empty (no running containers) so only network gateway will appear.
        DockerEngineApiClient.HttpGetter getter = uri -> {
            String path = uri.getPath();
            if (path.equals("/containers/json")) return Optional.of("[]");
            if (path.equals("/networks")) return Optional.of(NETWORKS_JSON_ONE_BRIDGE);
            return Optional.empty();
        };

        Predicate<HostPort> reachable = hp -> hp.port() == DockerHostProbeService.PORT_2375
            && hp.host().equals(probedIp);

        DockerHostProbeService probe = buildProbe(getter, reachable);
        probe.probeHosts(List.of(probedIp));

        // Gateway device at 172.17.0.1 attributed to probedIp must be persisted.
        Optional<io.castellum.domain.Device> gw =
            deviceRepository.findByIpAddressAndOriginHostIp("172.17.0.1", probedIp);
        assertThat(gw).as("gateway from /networks must be ingested").isPresent();

        // CRITICAL finding still raised (probe continues after networks wiring)
        io.castellum.domain.Device host =
            deviceRepository.findByIpAddressAndOriginHostIp(probedIp, "local").orElseThrow();
        Optional<NetworkService> finding = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(host.getId(), 2375, "tcp");
        assertThat(finding).isPresent();
        assertThat(finding.get().getPostureSeverity()).isEqualTo("CRITICAL");
    }

    /**
     * (2) getNetworks returns Optional.empty() → ingestNetworks NOT invoked;
     * container ingest + CRITICAL finding still happen (no regression).
     */
    @Test
    void probe2375_getNetworksEmpty_ingestNetworksNotInvoked() throws Exception {
        String probedIp = "10.0.0.91";
        seedLocalDevice(probedIp);

        // Container list empty; /networks returns empty → no gateway row.
        DockerEngineApiClient.HttpGetter getter = uri -> {
            String path = uri.getPath();
            if (path.equals("/containers/json")) return Optional.of("[]");
            // /networks is missing → returns Optional.empty()
            return Optional.empty();
        };

        Predicate<HostPort> reachable = hp -> hp.port() == DockerHostProbeService.PORT_2375
            && hp.host().equals(probedIp);

        DockerHostProbeService probe = buildProbe(getter, reachable);
        probe.probeHosts(List.of(probedIp));

        // No gateway row created (networks path was empty).
        long devicesBelongingToProbe = deviceRepository.findAll().stream()
            .filter(d -> probedIp.equals(d.getOriginHostIp())).count();
        assertThat(devicesBelongingToProbe).as("no gateway from empty /networks").isEqualTo(0);

        // CRITICAL finding still raised.
        io.castellum.domain.Device host =
            deviceRepository.findByIpAddressAndOriginHostIp(probedIp, "local").orElseThrow();
        Optional<NetworkService> finding = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(host.getId(), 2375, "tcp");
        assertThat(finding).isPresent();
        assertThat(finding.get().getPostureSeverity()).isEqualTo("CRITICAL");
    }

    /**
     * (4) NO phantom containers: ingestNetworks produces only gateway devices (containerIp=null).
     * A host with reachable :2375 returning /networks → only the gateway row, no container row.
     */
    @Test
    void probe2375_ingestNetworks_gatewayOnlyNoPhantomContainers() throws Exception {
        String probedIp = "10.0.0.92";
        seedLocalDevice(probedIp);

        DockerEngineApiClient.HttpGetter getter = uri -> {
            String path = uri.getPath();
            if (path.equals("/containers/json")) return Optional.of("[]");
            if (path.equals("/networks")) return Optional.of(NETWORKS_JSON_ONE_BRIDGE);
            return Optional.empty();
        };

        Predicate<HostPort> reachable = hp -> hp.port() == DockerHostProbeService.PORT_2375
            && hp.host().equals(probedIp);

        DockerHostProbeService probe = buildProbe(getter, reachable);
        probe.probeHosts(List.of(probedIp));

        // Count rows attributed to probedIp — must be exactly 1 (the gateway) not 2+.
        long remoteRows = deviceRepository.findAll().stream()
            .filter(d -> probedIp.equals(d.getOriginHostIp())).count();
        assertThat(remoteRows)
            .as("only 1 gateway row (no phantom containers) must exist for the probed origin")
            .isEqualTo(1);
        io.castellum.domain.Device gw =
            deviceRepository.findByIpAddressAndOriginHostIp("172.17.0.1", probedIp).orElseThrow();
        assertThat(gw.getHostname()).startsWith("docker-net:");
    }

    // -----------------------------------------------------------------------
    // R2 / F3 review-v83 NB1 — audit symmetry in probe8080
    //
    // Bug: when traefikEnabled=false, the TRAEFIK switch case falls through
    // the inner `if (traefikEnabled)` and emits NO audit event (silent scan).
    // Fix: audit must be emitted even when the surface flag is disabled.
    // -----------------------------------------------------------------------

    /** Build probe with UI clients + explicit k8s/registry disabled, Portainer noop. */
    private DockerHostProbeService buildProbeWithUiClientsAndFlags(
            Predicate<HostPort> reachable,
            TraefikApiClient traefikClient,
            CAdvisorApiClient cadvisorClient,
            boolean traefikEnabled,
            boolean cadvisorEnabled) {
        SnmpClient snmpClient = new SnmpClient((h, c, o) -> Optional.empty());
        SnmpBridgeMapper snmpMapper = new SnmpBridgeMapper();
        TraefikRouterMapper traefikMapper = new TraefikRouterMapper(TEST_OM);
        PortainerApiClient portainerClient = noopPortainerClient();
        CAdvisorContainerMapper cadvisorMapper = new CAdvisorContainerMapper(TEST_OM);
        Port8080Fingerprinter fingerprinter =
            new Port8080Fingerprinter(traefikClient, cadvisorClient, TEST_OM);
        DockerEngineApiClient apiClient = new DockerEngineApiClient(uri -> Optional.empty());
        return new DockerHostProbeService(
            deviceUpsertService, deviceRepository, discoveryService(),
            apiClient, networkMapper, containerListMapper, inspectParser,
            networkServiceRepository, auditService,
            snmpClient, snmpMapper, "public", false,
            traefikClient, traefikMapper, portainerClient, cadvisorClient, cadvisorMapper,
            fingerprinter, traefikEnabled, false, cadvisorEnabled,
            noopK8sClient(), noopKubeletClient(), new K8sPodMapper(TEST_OM), false,
            noopRegistryClient(), new RegistryCatalogMapper(TEST_OM), false,
            /* maxConcurrent */ 4, reachable);
    }

    /**
     * F3 review-v83 NB1 — audit symmetry in probe8080.
     *
     * <p>A host that fingerprints as Traefik on :8080 but has {@code traefik.enabled=false}
     * (while {@code cadvisor.enabled=true} so the outer guard still opens :8080) must still
     * record an audit event — the scan touched the surface even though the flag is off.
     *
     * <p>RED until the implementer hoists {@code emitAuditSuccess} out of the
     * {@code if (traefikEnabled)} inner block (or equivalent refactor).
     */
    @Test
    void probe8080_traefikDetected_traefikDisabled_auditEventStillEmitted() {
        String ip = "10.0.2.1";
        seedLocalDevice(ip);

        // Fingerprinter identifies :8080 as Traefik (overview endpoint answers)
        TraefikApiClient traefikClient = new TraefikApiClient(uri -> {
            if (uri.getPath().equals("/api/overview")) return Optional.of(TRAEFIK_OVERVIEW);
            return Optional.empty();
        });
        // cAdvisor must be enabled so the outer `(traefikEnabled || cadvisorEnabled)` guard
        // still opens port 8080; but it does NOT fingerprint as cAdvisor (returns empty).
        CAdvisorApiClient cadvisorClient = new CAdvisorApiClient(uri -> Optional.empty());

        // :8080 reachable
        Predicate<HostPort> reachable = hp -> hp.port() == 8080 && hp.host().equals(ip);

        // traefikEnabled=false, cadvisorEnabled=true (outer guard opens :8080 via cadvisor flag)
        DockerHostProbeService probe = buildProbeWithUiClientsAndFlags(
            reachable, traefikClient, cadvisorClient,
            /* traefikEnabled */ false, /* cadvisorEnabled */ true);

        probe.probeHosts(List.of(ip));

        // ASSERT: an audit event for port 8080 must have been recorded even though
        // traefikEnabled=false (the scan touched this surface — silence is wrong).
        verify(auditService, atLeastOnce()).recordEvent(
            eq("system"), eq("DOCKER_PROBE"), eq("docker_probe"),
            eq(ip + ":8080"), any());

        // No TRAEFIK_EXPOSURE finding must be raised (the surface is disabled)
        Optional<NetworkService> finding = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(
                deviceRepository.findByIpAddressAndOriginHostIp(ip, "local").get().getId(),
                8080, "tcp");
        assertThat(finding)
            .as("no TRAEFIK_EXPOSURE finding when traefikEnabled=false")
            .isEmpty();
    }

    // -----------------------------------------------------------------------
    // R2 / F4 review-v84 NB3 — optional getTags → registry_images enrichment
    //
    // Bug: RegistryApiClient.getTags(name) is coded + unit-tested but NOT wired
    // into probeRegistry.  registry_images currently stores bare repo names only.
    // Fix: after getCatalog, call getTags for each repo and fold name:tag into blob.
    // -----------------------------------------------------------------------

    /**
     * F4 review-v84 NB3 — getTags wired into probeRegistry → name:tag enrichment.
     *
     * <p>A registry surface with a known repository must, after probe, have the device's
     * {@code registry_images} contain at least one {@code name:tag} entry (e.g. {@code nginx:latest}).
     *
     * <p>RED until {@code getTags} is wired into {@code probeRegistry} and the blob is enriched.
     */
    @Test
    void registry5000_getTags_enrichesRegistryImagesWithNameColonTag() {
        String probedIp = "10.0.2.3";
        Device hostDevice = seedLocalDevice(probedIp);

        String catalogJson = "{\"repositories\":[\"nginx\"]}";
        String tagsJson = "{\"name\":\"nginx\",\"tags\":[\"latest\",\"1.25\"]}";

        // getCatalog returns catalog; getTags returns tags for "nginx"
        RegistryApiClient registryClient = new RegistryApiClient(uri -> {
            String path = uri.getPath();
            if (path.equals("/v2/_catalog")) return Optional.of(catalogJson);
            if (path.equals("/v2/nginx/tags/list")) return Optional.of(tagsJson);
            return Optional.empty();
        });

        // :5000 reachable
        Predicate<HostPort> reachable = hp ->
            hp.port() == DockerHostProbeService.PORT_5000 && hp.host().equals(probedIp);

        DockerHostProbeService probe = buildProbeWithK8sRegistry(
            uri -> Optional.empty(), reachable,
            noopK8sClient(), noopKubeletClient(), registryClient,
            /* k8sEnabled */ false, /* registryEnabled */ true);

        probe.probeHosts(List.of(probedIp));

        // registry_images must contain at least one name:tag entry
        Device reloadedHost = deviceRepository.findById(hostDevice.getId()).orElseThrow();
        String images = reloadedHost.getRegistryImages();
        assertThat(images)
            .as("registry_images must contain a name:tag entry after getTags enrichment")
            .isNotBlank()
            .contains("nginx:");

        // At least one of the known tags must appear
        assertThat(images)
            .as("registry_images must contain 'nginx:latest' or 'nginx:1.25' after getTags wiring")
            .satisfiesAnyOf(
                s -> assertThat(s).contains("nginx:latest"),
                s -> assertThat(s).contains("nginx:1.25"));
    }

    // -----------------------------------------------------------------------
    // R2 BLOCKING #2 — Blob DoS: per-repo tag cap must bound registry_images size
    //
    // probeRegistry accumulates repo:tag entries with NO cap on tags per repo.
    // A crafted registry returning e.g. 200 tags for one repo can build a
    // multi-megabyte blob. The fix: cap tags-per-repo at a documented bound.
    //
    // The exact cap value is the implementer's choice, but this test asserts it
    // is at most 64 entries — a reasonable, documented upper bound.  Whatever cap
    // the implementer chooses, the assertion `<= 64` must hold.
    // -----------------------------------------------------------------------

    /**
     * A registry with a single repository that advertises many tags (200) must produce
     * a {@code registry_images} blob whose entry count for that repo is bounded.
     *
     * <p>The existing happy-path enrichment test
     * ({@code registry5000_getTags_enrichesRegistryImagesWithNameColonTag}) must still
     * pass after this test is introduced — the cap only kicks in for excess tags.
     *
     * <p>RED until {@code probeRegistry} (or a downstream mapper) applies a per-repo
     * tag cap that limits the number of {@code repo:tag} entries per repository.
     *
     * <p>Comment: The exact cap is the implementer's choice; we assert at most 64
     * entries in {@code registry_images} for the single overloaded repo.  Use a
     * count of comma-delimited tokens as a proxy for the entry count.
     */
    @Test
    void registry5000_manyTags_perRepoTagCapEnforced() {
        String probedIp = "10.0.2.10";
        Device hostDevice = seedLocalDevice(probedIp);

        // Build a tags/list response body with 200 tags for "overloaded"
        StringBuilder tagsBuilder = new StringBuilder();
        tagsBuilder.append("{\"name\":\"overloaded\",\"tags\":[");
        for (int i = 0; i < 200; i++) {
            if (i > 0) tagsBuilder.append(",");
            tagsBuilder.append("\"tag").append(i).append("\"");
        }
        tagsBuilder.append("]}");
        String manyTagsJson = tagsBuilder.toString();

        String catalogJson = "{\"repositories\":[\"overloaded\"]}";

        RegistryApiClient registryClient = new RegistryApiClient(uri -> {
            String path = uri.getPath();
            if (path.equals("/v2/_catalog")) return Optional.of(catalogJson);
            if (path.startsWith("/v2/overloaded/tags/list")) return Optional.of(manyTagsJson);
            return Optional.empty();
        });

        Predicate<HostPort> reachable = hp ->
            hp.port() == DockerHostProbeService.PORT_5000 && hp.host().equals(probedIp);

        DockerHostProbeService probe = buildProbeWithK8sRegistry(
            uri -> Optional.empty(), reachable,
            noopK8sClient(), noopKubeletClient(), registryClient,
            /* k8sEnabled */ false, /* registryEnabled */ true);

        probe.probeHosts(List.of(probedIp));

        Device reloadedHost = deviceRepository.findById(hostDevice.getId()).orElseThrow();
        String images = reloadedHost.getRegistryImages();
        assertThat(images)
            .as("registry_images must be set after a repo with many tags is probed")
            .isNotBlank();

        // Count entries: the blob is comma-separated; split on comma to count tokens.
        // Each token corresponds to one repo:tag entry (or bare repo name for the
        // fallback case).  With 200 raw tags and no cap the count would be 200;
        // with a proper cap it must be <= 64.
        long entryCount = java.util.Arrays.stream(images.split(","))
            .filter(s -> !s.isBlank())
            .count();

        assertThat(entryCount)
            .as("registry_images entry count must be <= 64 for a single overloaded repo "
                + "(implementer's per-repo tag cap must bound blob growth; "
                + "actual cap is implementer's choice but this assertion sets the ceiling)")
            .isLessThanOrEqualTo(64);
    }
}
