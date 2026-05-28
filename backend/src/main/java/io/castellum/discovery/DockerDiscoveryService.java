package io.castellum.discovery;

import io.castellum.audit.AuditService;
import io.castellum.domain.Device;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Discovers running Docker containers via the local {@code docker} CLI and renders them into
 * the {@link Device} inventory so the existing client-side topology builder
 * ({@code frontend/src/lib/gatewayEdges.ts}) draws the operator's intended graph with NO new
 * edge code:
 *
 * <ul>
 *   <li><b>Same-network star.</b> Each container is upserted with its real IP on its primary
 *       docker network. Containers sharing a network share a {@code /24}, so the gateway-edge
 *       builder auto-stars them around the {@code .1} gateway of that subnet. A synthetic
 *       gateway {@link Device} is upserted at each network's gateway IP to give the star a real
 *       centre node.</li>
 *   <li><b>Host bridge only when published.</b> A container's {@link DiscoveryScope} is
 *       {@link DiscoveryScope#DOCKER_BRIDGE} iff it publishes a host port, else
 *       {@link DiscoveryScope#HOME}. The edge builder draws a {@code docker-bridge} edge from
 *       {@code host.docker.internal} directly to every {@code DOCKER_BRIDGE} device — so only
 *       port-publishing containers link to the host, and that edge goes straight to the
 *       container (not via the gateway). Internal-only containers stay on their network star.</li>
 * </ul>
 *
 * <p>Idempotent: re-running upserts every device in place (keyed on IP). The run emits one
 * {@code DOCKER_DISCOVERY} audit event.
 *
 * <p><b>Scope authority.</b> The "publishes a host port" signal is orthogonal to a container's
 * bridge-subnet IP, so the IP-range {@link DiscoveryScopeClassifier} cannot derive it (compose
 * stacks land on {@code 172.18+}, {@code 172.19+}, …). The service therefore upserts via
 * {@link DeviceUpsertService#upsertWithScope(Discovery, DiscoveryScope)}, which writes the
 * explicit scope authoritatively on both insert and update.
 */
@Service
public class DockerDiscoveryService {

    private static final Logger log = LoggerFactory.getLogger(DockerDiscoveryService.class);

    private final DockerCliClient cli;
    private final DockerInspectParser parser;
    private final DeviceUpsertService upsertService;
    private final AuditService auditService;
    private final Clock clock;

    public DockerDiscoveryService(DockerCliClient cli,
                                  DockerInspectParser parser,
                                  DeviceUpsertService upsertService,
                                  AuditService auditService,
                                  Clock clock) {
        this.cli = cli;
        this.parser = parser;
        this.upsertService = upsertService;
        this.auditService = auditService;
        this.clock = clock;
    }

    /**
     * Runs one discovery pass.
     *
     * @return a summary of containers + synthetic gateways upserted
     * @throws DiscoveryUnavailableException if the docker CLI is absent/unreachable or fails
     */
    public DockerDiscoveryResponse discover() throws DiscoveryUnavailableException {
        List<String> ids = cli.listRunningContainerIds();
        String json = cli.inspect(ids);
        List<DockerContainer> containers = parser.parse(json);

        Instant observedAt = clock.instant();
        List<Long> deviceIds = new ArrayList<>();

        // Dedupe synthetic gateways by gateway-IP so one network with N containers yields a
        // single centre node. LinkedHashMap keeps a deterministic gateway name (first wins).
        Map<String, String> gatewaysByIp = new LinkedHashMap<>();

        int containerCount = 0;
        for (DockerContainer c : containers) {
            DockerContainer.DockerNetworkAttachment primary = c.primaryNetwork();
            if (primary == null) {
                // No usable IP (e.g. host-network or none-network container) — cannot key a
                // device upsert. Skip but log so operators can see why it's absent.
                log.debug("Skipping container '{}' — no network attachment with a usable IP", c.name());
                continue;
            }
            DiscoveryScope scope = c.publishesHostPort()
                ? DiscoveryScope.DOCKER_BRIDGE
                : DiscoveryScope.HOME;
            Discovery disc = new Discovery(
                primary.containerIp(),
                null,                       // docker inspect carries no host-relevant MAC for topology
                c.name(),                   // container name → hostname (topology label)
                DiscoverySource.DOCKER,
                observedAt,
                null);                      // no host iface for a container address
            Device saved = upsertService.upsertWithScope(disc, scope);
            deviceIds.add(saved.getId());
            containerCount++;

            // Record this network's gateway for synthetic-centre upsert.
            String gwIp = primary.gatewayIp();
            if (gwIp != null && !gwIp.isBlank()) {
                gatewaysByIp.putIfAbsent(gwIp, primary.networkName());
            }
        }

        // Upsert one synthetic gateway device per docker network so the star has a real centre.
        // Gateways are HOME-scope (never bridged to the host themselves) and named after the
        // docker network. They are NOT the host node — host.docker.internal is a separate
        // HOME device seeded by the host/passive discovery path.
        int gatewayCount = 0;
        for (Map.Entry<String, String> gw : gatewaysByIp.entrySet()) {
            String gwIp = gw.getKey();
            String networkName = gw.getValue();
            Discovery disc = new Discovery(
                gwIp,
                null,
                "docker-net:" + networkName,
                DiscoverySource.DOCKER,
                observedAt,
                null);
            Device saved = upsertService.upsertWithScope(disc, DiscoveryScope.HOME);
            deviceIds.add(saved.getId());
            gatewayCount++;
        }

        int updated = containerCount + gatewayCount;
        auditService.recordEvent(
            "discovery",
            "DOCKER_DISCOVERY",
            "discovery",
            "docker",
            Map.of(
                "containers", containerCount,
                "gateways", gatewayCount,
                "updated", updated));

        log.info("Docker discovery upserted {} containers + {} gateways ({} devices)",
            containerCount, gatewayCount, updated);
        return new DockerDiscoveryResponse(containerCount, gatewayCount, updated, deviceIds);
    }
}
