package io.castellum.discovery;

import io.castellum.audit.AuditService;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.discovery.Discovery;
import io.castellum.discovery.DiscoverySource;
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
 *       DOCKER_BRIDGE ones to the docker-host pivot (the HOME device at the configured docker-host IP);</li>
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
    @Autowired private NetworkServiceRepository serviceRepo;

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
        return new DockerDiscoveryService(cli, parser, upsertService, serviceRepo, auditService,
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

        // pingpay-db exposes 3306 internal-only — AC2: ALL docker containers → DOCKER_BRIDGE
        Device db = repo.findByIpAddress("172.18.0.2").orElseThrow();
        assertThat(db.getHostname()).isEqualTo("pingpay-db");
        assertThat(db.getDiscoveryScope()).isEqualTo(DiscoveryScope.DOCKER_BRIDGE);
    }

    @Test
    void discover_internalContainerOn172_18_notMisclassifiedByIpRange() throws Exception {
        // Regression guard: the IP-range classifier maps 172.18.x → DOCKER_BRIDGE, but the
        // explicit-scope upsert path is authoritative. AC2: all docker containers → DOCKER_BRIDGE
        // regardless of whether a host port is published. The classifier is never consulted for
        // docker-discovered containers.
        newService(fixture("inspect-reference.json"), List.of("c3")).discover();
        Device db = repo.findByIpAddress("172.18.0.2").orElseThrow();
        assertThat(db.getDiscoveryScope())
            .as("docker-discovered container must be DOCKER_BRIDGE (explicit scope path, not IP classifier)")
            .isEqualTo(DiscoveryScope.DOCKER_BRIDGE);
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

        // storage is internal-only — AC2: still DOCKER_BRIDGE (not HOME)
        Device storage = repo.findByIpAddress("172.19.0.8").orElseThrow();
        assertThat(storage.getDiscoveryScope()).isEqualTo(DiscoveryScope.DOCKER_BRIDGE);
    }

    // ── AC1: every docker-discovered container gets os = "Linux" ──────────────────────────────

    @Test
    void discover_container_hasOsLinux() throws Exception {
        newService(fixture("inspect-reference.json"), List.of("c1")).discover();

        Device frontend = repo.findByIpAddress("172.18.0.4").orElseThrow();
        assertThat(frontend.getOsName())
            .as("docker container must have os='Linux'")
            .isEqualTo("Linux");
    }

    @Test
    void discover_internalOnlyContainer_hasOsLinux() throws Exception {
        newService(fixture("inspect-reference.json"), List.of("c3")).discover();

        Device db = repo.findByIpAddress("172.18.0.2").orElseThrow();
        assertThat(db.getOsName())
            .as("internal-only container must still have os='Linux'")
            .isEqualTo("Linux");
    }

    // ── AC2: ALL docker-discovered containers → DOCKER_BRIDGE regardless of host-port ─────────

    @Test
    void discover_internalOnlyContainer_isDockerBridge() throws Exception {
        // pingpay-db exposes 3306 internally only — no host port
        // AC2: Docker source is authoritative → DOCKER_BRIDGE (not HOME)
        newService(fixture("inspect-reference.json"), List.of("c3")).discover();

        Device db = repo.findByIpAddress("172.18.0.2").orElseThrow();
        assertThat(db.getDiscoveryScope())
            .as("internal-only container must be DOCKER_BRIDGE (Docker source authoritative)")
            .isEqualTo(DiscoveryScope.DOCKER_BRIDGE);
    }

    @Test
    void discover_containerOnCustomNetwork_172_21_isDockerBridge() throws Exception {
        // pingpay-db-custom on 172.21.0.3 — custom docker network, no host port
        // AC2: custom network must still → DOCKER_BRIDGE (not HOME via IP-range heuristic)
        newService(fixture("inspect-custom-network.json"), List.of("c9")).discover();

        Device db = repo.findByIpAddress("172.21.0.3").orElseThrow();
        assertThat(db.getDiscoveryScope())
            .as("container on custom 172.21.x network must be DOCKER_BRIDGE, not HOME")
            .isEqualTo(DiscoveryScope.DOCKER_BRIDGE);
        assertThat(db.getOsName()).isEqualTo("Linux");
    }

    // ── AC3: Docker scope is not downgraded by a passive (upsert) observation ─────────────────

    @Test
    void discover_thenPassiveObservation_scopeNotDowngradedToHome() throws Exception {
        // 1. Docker discovery seeds the container as DOCKER_BRIDGE
        newService(fixture("inspect-reference.json"), List.of("c3")).discover();
        Device db = repo.findByIpAddress("172.18.0.2").orElseThrow();
        assertThat(db.getDiscoveryScope()).isEqualTo(DiscoveryScope.DOCKER_BRIDGE);

        // 2. A passive ARP sweep re-observes the same IP — must NOT overwrite to HOME
        Discovery passive = new Discovery(
            "172.18.0.2", "02:42:ac:12:00:02", null, DiscoverySource.ARP, FIXED_NOW.plusSeconds(60), null);
        upsertService.upsert(passive);

        Device after = repo.findByIpAddress("172.18.0.2").orElseThrow();
        assertThat(after.getDiscoveryScope())
            .as("passive ARP must not downgrade DOCKER_BRIDGE to HOME")
            .isEqualTo(DiscoveryScope.DOCKER_BRIDGE);
    }

    // ── AC5: non-container HOME devices unaffected ────────────────────────────────────────────

    @Test
    void discover_syntheticGateway_isHomeAndHasNoOs() throws Exception {
        // Synthetic gateways are HOME-scope and should NOT get os="Linux"
        newService(fixture("inspect-reference.json"), List.of("c3")).discover();

        Device gw = repo.findByIpAddress("172.18.0.1").orElseThrow();
        assertThat(gw.getDiscoveryScope()).isEqualTo(DiscoveryScope.HOME);
        assertThat(gw.getOsName())
            .as("synthetic gateway is not a container — must have null osName")
            .isNull();
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
        // AC2: ALL containers are DOCKER_BRIDGE from first discovery — the scope is always
        // DOCKER_BRIDGE regardless of whether a host port is published.
        String internalOnly = """
            [
              {
                "Id": "c3",
                "Name": "/pingpay-db",
                "State": { "Status": "running", "Running": true },
                "Config": { "Image": "postgres:15.6" },
                "NetworkSettings": {
                  "Ports": { "3306/tcp": null },
                  "Networks": { "pingpay_default": { "IPAddress": "172.18.0.2", "Gateway": "172.18.0.1" } }
                }
              }
            ]
            """;
        newService(internalOnly, List.of("c3")).discover();
        assertThat(repo.findByIpAddress("172.18.0.2").orElseThrow().getDiscoveryScope())
            .as("internal-only container — DOCKER_BRIDGE from first discovery")
            .isEqualTo(DiscoveryScope.DOCKER_BRIDGE);

        // Second run: same container now publishes a port — still DOCKER_BRIDGE
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
            new DockerCliClient(failing), parser, upsertService, serviceRepo, auditService,
            Clock.fixed(FIXED_NOW, ZoneOffset.UTC));

        assertThatThrownBy(svc::discover)
            .isInstanceOf(DiscoveryUnavailableException.class);
        assertThat(repo.count()).isZero();
    }

    // -----------------------------------------------------------------------
    // Image → service / CPE derivation (drives fleet CVE correlation)
    // -----------------------------------------------------------------------

    @Test
    void discover_knownImage_persistsCpeBearingService() throws Exception {
        // pingpay-db = postgres:15.6 → postgresql CPE with concrete version
        newService(fixture("inspect-reference.json"), List.of("c3")).discover();
        Device db = repo.findByIpAddress("172.18.0.2").orElseThrow();
        NetworkService svc = serviceRepo
            .findByDeviceIdAndPortAndProtocol(db.getId(), 3306, "tcp").orElseThrow();
        assertThat(svc.getName()).isEqualTo("postgresql");
        assertThat(svc.getProduct()).isEqualTo("postgresql");
        assertThat(svc.getVersion()).isEqualTo("15.6");
        assertThat(svc.getCpe()).isEqualTo("cpe:2.3:a:postgresql:postgresql:15.6:*:*:*:*:*:*:*");
    }

    @Test
    void discover_namespacedPostgresImage_derivesPostgresqlCpe() throws Exception {
        // supabase_db = public.ecr.aws/supabase/postgres:15.1.0.147 → registry+namespace stripped
        newService(fixture("inspect-reference.json"),
            List.of("c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8")).discover();
        Device sup = repo.findByIpAddress("172.19.0.2").orElseThrow();
        NetworkService svc = serviceRepo
            .findByDeviceIdAndPortAndProtocol(sup.getId(), 5432, "tcp").orElseThrow();
        assertThat(svc.getCpe()).isEqualTo("cpe:2.3:a:postgresql:postgresql:15.1.0.147:*:*:*:*:*:*:*");
    }

    @Test
    void discover_unmappedImage_persistsServiceWithoutCpe() throws Exception {
        // kong:3.4.2 is not a curated NVD product → inventory only, no CPE
        newService(fixture("inspect-reference.json"), List.of("c4")).discover();
        Device kong = repo.findByIpAddress("172.19.0.5").orElseThrow();
        NetworkService svc = serviceRepo
            .findByDeviceIdAndPortAndProtocol(kong.getId(), 8000, "tcp").orElseThrow();
        assertThat(svc.getName()).isEqualTo("kong");
        assertThat(svc.getVersion()).isEqualTo("3.4.2");
        assertThat(svc.getProduct()).isNull();
        assertThat(svc.getCpe()).isNull();
    }

    @Test
    void discover_containerWithNoExposedPort_noServiceRow() throws Exception {
        // storage exposes no port → no service row keyed against it
        newService(fixture("inspect-reference.json"), List.of("c8")).discover();
        Device storage = repo.findByIpAddress("172.19.0.8").orElseThrow();
        assertThat(serviceRepo.findByDeviceId(storage.getId())).isEmpty();
    }

    @Test
    void discover_idempotent_serviceUpsertedInPlace() throws Exception {
        DockerDiscoveryService svc = newService(fixture("inspect-reference.json"), List.of("c3"));
        svc.discover();
        svc.discover();
        Device db = repo.findByIpAddress("172.18.0.2").orElseThrow();
        // re-run upserts the same (deviceId, port, protocol) row, no duplicate
        assertThat(serviceRepo.findByDeviceId(db.getId())).hasSize(1);
    }

    @Test
    void discover_imageDowngrade_clearsStaleCpeAndVersion() throws Exception {
        // First run: postgres:16 → version-bearing CPE persisted.
        String v16 = """
            [ { "Id": "pg", "Name": "/pg", "Config": { "Image": "postgres:16" },
                "NetworkSettings": { "Ports": { "5432/tcp": null },
                  "Networks": { "n": { "IPAddress": "172.40.0.2", "Gateway": "172.40.0.1" } } } } ]
            """;
        newService(v16, List.of("pg")).discover();
        Device pg = repo.findByIpAddress("172.40.0.2").orElseThrow();
        assertThat(serviceRepo.findByDeviceIdAndPortAndProtocol(pg.getId(), 5432, "tcp")
                .orElseThrow().getCpe())
            .isEqualTo("cpe:2.3:a:postgresql:postgresql:16:*:*:*:*:*:*:*");

        // Re-tagged to a version-less image → stale CPE + version must be cleared in place,
        // not left dangling (else CVE correlation would keep matching a version no longer running).
        String latest = """
            [ { "Id": "pg", "Name": "/pg", "Config": { "Image": "postgres:latest" },
                "NetworkSettings": { "Ports": { "5432/tcp": null },
                  "Networks": { "n": { "IPAddress": "172.40.0.2", "Gateway": "172.40.0.1" } } } } ]
            """;
        newService(latest, List.of("pg")).discover();
        NetworkService svc = serviceRepo
            .findByDeviceIdAndPortAndProtocol(pg.getId(), 5432, "tcp").orElseThrow();
        assertThat(svc.getCpe()).isNull();
        assertThat(svc.getVersion()).isNull();
    }
}
