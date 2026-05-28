package io.castellum.discovery;

import io.castellum.audit.AuditService;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * End-to-end container→{@link Device} mapping test for {@link DockerDiscoveryService} against a
 * real {@link DeviceRepository} + {@link DeviceUpsertService} ({@code @DataJpaTest}), with the
 * {@link DockerCliClient} stubbed to return fixture JSON so no {@code docker} process spawns.
 *
 * <p>Asserts the operator's topology model:
 * <ul>
 *   <li>container IP = its IP on its primary docker network;</li>
 *   <li>hostname = container name;</li>
 *   <li>source = {@link DiscoverySource#DOCKER};</li>
 *   <li>scope = {@link DiscoveryScope#DOCKER_BRIDGE} iff it publishes a host port, else
 *       {@link DiscoveryScope#HOME} — the live edge logic then bridges only the
 *       DOCKER_BRIDGE ones to {@code host.docker.internal};</li>
 *   <li>one synthetic gateway device per docker network at its {@code .1} gateway;</li>
 *   <li>idempotent re-run (no duplicate rows).</li>
 * </ul>
 */
@DataJpaTest
@Import({DeviceUpsertService.class, DiscoveryScopeClassifier.class, DockerInspectParser.class})
class DockerDiscoveryServiceTest {

    static final Instant FIXED_NOW = Instant.parse("2026-05-28T12:00:00Z");

    @Autowired private DeviceRepository repo;
    @Autowired private DeviceUpsertService upsertService;
    @Autowired private DockerInspectParser parser;

    // DockerDiscoveryService is constructed by hand (newService) rather than wired into the
    // context, so AuditService is a plain Mockito mock — not a @MockBean.
    private final AuditService auditService = Mockito.mock(AuditService.class);

    private DockerDiscoveryService newService(String inspectJson, List<String> ids) {
        DockerCliClient.CommandRunner runner = argv -> {
            if (argv.contains("ps")) {
                return new DockerCliClient.CommandResult(0, String.join("\n", ids), "");
            }
            return new DockerCliClient.CommandResult(0, inspectJson, "");
        };
        DockerCliClient cli = new DockerCliClient(runner);
        return new DockerDiscoveryService(cli, parser, upsertService, auditService,
            Clock.fixed(FIXED_NOW, ZoneOffset.UTC));
    }

    private static String fixture(String name) throws IOException {
        try (InputStream in = DockerDiscoveryServiceTest.class.getResourceAsStream("/docker/" + name)) {
            assertNotNull(in, "fixture /docker/" + name + " must be on the test classpath");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @BeforeEach
    void setUp() {
        repo.deleteAll();
    }

    // -----------------------------------------------------------------------
    // Full reference stack
    // -----------------------------------------------------------------------

    @Test
    void discover_referenceStack_upsertsContainersAndGateways() throws Exception {
        DockerDiscoveryService svc = newService(fixture("inspect-reference.json"),
            List.of("c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8"));

        DockerDiscoveryResponse res = svc.discover();

        // 8 containers (all have a usable IP) + 2 synthetic gateways (172.18.0.1, 172.19.0.1)
        assertThat(res.containers()).isEqualTo(8);
        assertThat(res.gateways()).isEqualTo(2);
        assertThat(res.updated()).isEqualTo(10);
        assertThat(res.deviceIds()).hasSize(10);
        assertThat(repo.count()).isEqualTo(10L);
    }

    @Test
    void discover_publishedContainer_mappedToDockerBridge() throws Exception {
        newService(fixture("inspect-reference.json"), List.of("c1")).discover();

        Device frontend = repo.findByIpAddress("172.18.0.4").orElseThrow();
        assertThat(frontend.getHostname()).isEqualTo("pingpay-frontend");
        assertThat(frontend.getDiscoverySource()).isEqualTo(DiscoverySource.DOCKER);
        assertThat(frontend.getDiscoveryScope()).isEqualTo(DiscoveryScope.DOCKER_BRIDGE);
    }

    @Test
    void discover_internalOnlyContainer_mappedToHome() throws Exception {
        newService(fixture("inspect-reference.json"), List.of("c3")).discover();

        // pingpay-db exposes 3306 internal-only → HOME (NOT bridged to host)
        Device db = repo.findByIpAddress("172.18.0.2").orElseThrow();
        assertThat(db.getHostname()).isEqualTo("pingpay-db");
        assertThat(db.getDiscoveryScope()).isEqualTo(DiscoveryScope.HOME);
    }

    @Test
    void discover_internalContainerOn172_18_notMisclassifiedByIpRange() throws Exception {
        // Regression guard: the IP-range classifier maps 172.18.x → DOCKER_BRIDGE, but the
        // internal-only db must be HOME. The explicit-scope upsert path overrides the classifier.
        newService(fixture("inspect-reference.json"), List.of("c3")).discover();
        Device db = repo.findByIpAddress("172.18.0.2").orElseThrow();
        assertThat(db.getDiscoveryScope())
            .as("internal-only container on a docker-bridge subnet must be HOME, not DOCKER_BRIDGE")
            .isEqualTo(DiscoveryScope.HOME);
    }

    @Test
    void discover_syntheticGateway_perNetwork_atDot1() throws Exception {
        newService(fixture("inspect-reference.json"),
            List.of("c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8")).discover();

        // pingpay gateway 172.18.0.1, supabase gateway 172.19.0.1 — both HOME, named after network
        Device gw18 = repo.findByIpAddress("172.18.0.1").orElseThrow();
        assertThat(gw18.getDiscoveryScope()).isEqualTo(DiscoveryScope.HOME);
        assertThat(gw18.getHostname()).isEqualTo("docker-net:pingpay_default");
        assertThat(gw18.getDiscoverySource()).isEqualTo(DiscoverySource.DOCKER);

        Device gw19 = repo.findByIpAddress("172.19.0.1").orElseThrow();
        assertThat(gw19.getDiscoveryScope()).isEqualTo(DiscoveryScope.HOME);
        assertThat(gw19.getHostname()).isEqualTo("docker-net:supabase_network_pingpay");
    }

    @Test
    void discover_supabaseContainersOnDistinctSubnet() throws Exception {
        newService(fixture("inspect-reference.json"),
            List.of("c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8")).discover();

        // kong publishes 54321 → DOCKER_BRIDGE, on the 172.19.x star
        Device kong = repo.findByIpAddress("172.19.0.5").orElseThrow();
        assertThat(kong.getHostname()).isEqualTo("supabase_kong_pingpay");
        assertThat(kong.getDiscoveryScope()).isEqualTo(DiscoveryScope.DOCKER_BRIDGE);

        // storage is internal-only → HOME
        Device storage = repo.findByIpAddress("172.19.0.8").orElseThrow();
        assertThat(storage.getDiscoveryScope()).isEqualTo(DiscoveryScope.HOME);
    }

    // -----------------------------------------------------------------------
    // Idempotency + scope-flip on re-run
    // -----------------------------------------------------------------------

    @Test
    void discover_idempotent_reRunNoDuplicates() throws Exception {
        DockerDiscoveryService svc = newService(fixture("inspect-reference.json"),
            List.of("c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8"));
        svc.discover();
        long afterFirst = repo.count();
        svc.discover();

        assertThat(repo.count()).isEqualTo(afterFirst);
        assertThat(afterFirst).isEqualTo(10L);
    }

    @Test
    void discover_containerStartsPublishing_scopeFlipsHomeToDockerBridge() throws Exception {
        // First run: db is internal-only → HOME
        newService(fixture("inspect-reference.json"), List.of("c3")).discover();
        assertThat(repo.findByIpAddress("172.18.0.2").orElseThrow().getDiscoveryScope())
            .isEqualTo(DiscoveryScope.HOME);

        // Second run: same container now publishes a port → must flip to DOCKER_BRIDGE in place
        String published = """
            [
              {
                "Id": "c3",
                "Name": "/pingpay-db",
                "NetworkSettings": {
                  "Ports": { "3306/tcp": [ { "HostIp": "0.0.0.0", "HostPort": "3306" } ] },
                  "Networks": { "pingpay_default": { "IPAddress": "172.18.0.2", "Gateway": "172.18.0.1" } }
                }
              }
            ]
            """;
        newService(published, List.of("c3")).discover();

        Device db = repo.findByIpAddress("172.18.0.2").orElseThrow();
        assertThat(db.getDiscoveryScope()).isEqualTo(DiscoveryScope.DOCKER_BRIDGE);
    }

    // -----------------------------------------------------------------------
    // No-IP container + empty daemon + audit + failure propagation
    // -----------------------------------------------------------------------

    @Test
    void discover_containerWithNoUsableIp_skipped() throws Exception {
        String json = """
            [ { "Id": "hn", "Name": "/host-net", "NetworkSettings": { "Ports": {}, "Networks": {} } } ]
            """;
        DockerDiscoveryResponse res = newService(json, List.of("hn")).discover();
        assertThat(res.containers()).isZero();
        assertThat(res.gateways()).isZero();
        assertThat(repo.count()).isZero();
    }

    @Test
    void discover_noRunningContainers_zeroAndNoRows() throws Exception {
        DockerDiscoveryResponse res = newService("[]", List.of()).discover();
        assertThat(res.updated()).isZero();
        assertThat(repo.count()).isZero();
    }

    @Test
    void discover_emitsAuditEvent() throws Exception {
        newService(fixture("inspect-reference.json"), List.of("c1")).discover();
        org.mockito.Mockito.verify(auditService).recordEvent(
            org.mockito.ArgumentMatchers.eq("discovery"),
            org.mockito.ArgumentMatchers.eq("DOCKER_DISCOVERY"),
            org.mockito.ArgumentMatchers.eq("discovery"),
            org.mockito.ArgumentMatchers.eq("docker"),
            org.mockito.ArgumentMatchers.any());
    }

    @Test
    void discover_dockerUnavailable_propagatesDiscoveryUnavailable() {
        DockerCliClient.CommandRunner failing = argv -> {
            throw new IOException("docker: command not found");
        };
        DockerDiscoveryService svc = new DockerDiscoveryService(
            new DockerCliClient(failing), parser, upsertService, auditService,
            Clock.fixed(FIXED_NOW, ZoneOffset.UTC));

        assertThatThrownBy(svc::discover)
            .isInstanceOf(DiscoveryUnavailableException.class);
        assertThat(repo.count()).isZero();
    }
}
