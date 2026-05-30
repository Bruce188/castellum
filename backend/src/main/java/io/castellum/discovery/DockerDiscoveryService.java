package io.castellum.discovery;

import io.castellum.audit.AuditService;
import io.castellum.discovery.DockerContainer.DockerNetworkAttachment;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
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
 * <p>After the container ingest pass, the LOCAL {@link #discover()} path runs a best-effort
 * default-bridge segmentation check: one {@code docker network inspect -- bridge} call (READ-ONLY)
 * surfaces the actual {@code enable_icc} flag and container membership, then emits a posture
 * finding on the synthetic {@code docker-net:bridge} gateway device when warranted.</p>
 *
 * <ul>
 *   <li><b>Same-network star.</b> Each container is upserted with its real IP on its primary
 *       docker network. Containers sharing a network share a {@code /24}, so the gateway-edge
 *       builder auto-stars them around the {@code .1} gateway of that subnet. A synthetic
 *       gateway {@link Device} is upserted at each network's gateway IP to give the star a real
 *       centre node.</li>
 *   <li><b>All containers are DOCKER_BRIDGE.</b> Every discovered container receives
 *       {@link DiscoveryScope#DOCKER_BRIDGE} — the Docker source is authoritative for scope
 *       regardless of whether the container publishes a host port. Custom docker networks
 *       (172.18+, 172.20+, …) would be mis-classified {@link DiscoveryScope#HOME} by the
 *       IP-range heuristic; Docker source always wins. The edge builder draws a
 *       {@code docker-bridge} edge from {@code host.docker.internal} to every
 *       {@code DOCKER_BRIDGE} device, linking all containers to the host pivot.</li>
 * </ul>
 *
 * <p>Idempotent: re-running upserts every device in place (keyed on IP). The run emits one
 * {@code DOCKER_DISCOVERY} audit event.
 *
 * <p><b>Scope authority.</b> Custom docker networks can use any RFC1918 range, so the
 * IP-range {@link DiscoveryScopeClassifier} cannot reliably classify containers (compose
 * stacks land on {@code 172.18+}, {@code 172.19+}, …). The Docker source is therefore
 * authoritative: all containers are upserted as {@link DiscoveryScope#DOCKER_BRIDGE} via
 * {@link DeviceUpsertService#upsertWithScope(Discovery, DiscoveryScope)}, which writes the
 * explicit scope authoritatively on both insert and update.
 */
@Service
public class DockerDiscoveryService {

    private static final Logger log = LoggerFactory.getLogger(DockerDiscoveryService.class);

    /**
     * Protocol-family label for the default-bridge ICC posture finding.
     * Mirrors the PROTOCOL_FAMILY_* convention from DockerHostProbeService.
     */
    public static final String PROTOCOL_FAMILY_DEFAULT_BRIDGE_ICC = "DEFAULT_BRIDGE_ICC";

    /**
     * Sentinel port for the default-bridge finding row.
     *
     * <p>{@link io.castellum.domain.NetworkService#port} is annotated {@code @Min(1) @Max(65535)};
     * a {@code 0} sentinel fails Bean Validation. Port 65535 (top of the valid range) is chosen
     * because it cannot collide with a real listening-service row (no daemon binds the top of the
     * ephemeral range by convention), and it upserts idempotently on (deviceId, 65535, "tcp")
     * across re-runs.
     */
    private static final int DEFAULT_BRIDGE_FINDING_PORT = 65535;

    /** Transport protocol for the sentinel finding row — see {@link #DEFAULT_BRIDGE_FINDING_PORT}. */
    private static final String DEFAULT_BRIDGE_FINDING_PROTOCOL = "tcp";

    private final DockerCliClient cli;
    private final DockerInspectParser parser;
    private final DeviceUpsertService upsertService;
    private final DeviceRepository deviceRepository;
    private final NetworkServiceRepository networkServiceRepository;
    private final AuditService auditService;
    private final Clock clock;

    public DockerDiscoveryService(DockerCliClient cli,
                                  DockerInspectParser parser,
                                  DeviceUpsertService upsertService,
                                  DeviceRepository deviceRepository,
                                  NetworkServiceRepository networkServiceRepository,
                                  AuditService auditService,
                                  Clock clock) {
        this.cli = cli;
        this.parser = parser;
        this.upsertService = upsertService;
        this.deviceRepository = deviceRepository;
        this.networkServiceRepository = networkServiceRepository;
        this.auditService = auditService;
        this.clock = clock;
    }

    /**
     * Runs one discovery pass using the local Docker CLI.
     *
     * <p>Parses running containers via the CLI, then delegates to
     * {@link #ingest(List, OriginContext, Instant)} with {@link OriginContext#local()}.
     * The local path is byte-identical to the pre-refactor behaviour.
     *
     * @return a summary of containers + synthetic gateways upserted
     * @throws DiscoveryUnavailableException if the docker CLI is absent/unreachable or fails
     */
    public DockerDiscoveryResponse discover() throws DiscoveryUnavailableException {
        List<String> ids = cli.listRunningContainerIds();
        String json = cli.inspect(ids);
        List<DockerContainer> containers = parser.parse(json);
        Instant now = clock.instant();
        DockerDiscoveryResponse response = ingest(containers, OriginContext.local(), now);
        // Best-effort default-bridge segmentation check (LOCAL path only — invariant 5).
        // Runs AFTER ingest() so the docker-net:bridge gateway device exists for the finding anchor.
        checkDefaultBridge(now);
        return response;
    }

    /**
     * Shared ingest: persists a pre-parsed list of {@link DockerContainer}s attributed to the
     * given {@link OriginContext}.
     *
     * <p>Used by BOTH the local CLI path ({@link #discover()} passes {@link OriginContext#local()})
     * and the remote Docker Host Probe (Phase 4, passes {@link OriginContext#of(String, String)}
     * with the probed host's IP and hostname). The local path is byte-identical to the
     * pre-refactor behaviour — origin='local' dedup semantics are unchanged.
     *
     * <p>Intentionally NOT {@code @Transactional}: each container/gateway upsert + service save
     * commits independently. A pass is fully idempotent — devices keyed on (ip, origin), services
     * on (deviceId, port, protocol) — so a mid-pass failure is healed by re-running.
     *
     * @param containers the parsed list of containers (e.g. from {@link DockerInspectParser#parse})
     * @param origin     the origin context: local discovery or remote-probe host
     * @param observedAt the observation timestamp
     * @return a summary of containers + synthetic gateways upserted
     */
    public DockerDiscoveryResponse ingest(List<DockerContainer> containers,
                                          OriginContext origin,
                                          Instant observedAt) {
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
            // AC2: Docker discovery is the authoritative source for scope.
            // ALL discovered containers are DOCKER_BRIDGE regardless of whether they
            // publish a host port. Custom docker networks (172.20+, 172.21+, …) would
            // be mis-classified HOME by the IP-range heuristic; Docker source wins.
            DiscoveryScope scope = DiscoveryScope.DOCKER_BRIDGE;
            Discovery disc = new Discovery(
                primary.containerIp(),
                null,                       // docker inspect carries no host-relevant MAC for topology
                c.name(),                   // container name → hostname (topology label)
                DiscoverySource.DOCKER,
                observedAt,
                null,                       // no host iface for a container address
                c.publishesHostPort());     // propagate host-port flag from parsed container
            Device saved = upsertService.upsertWithScope(disc, scope, origin);
            // Populate the container's docker network name (e.g. "bridge", "pingpay_default").
            // Post-upsert mutation mirrors the registryImages / originHostIp re-save pattern.
            // primary.networkName() is always non-null for containers that reach this path.
            saved.setNetworkName(primary.networkName());
            deviceRepository.save(saved);
            deviceIds.add(saved.getId());
            containerCount++;

            // Persist the container's primary service (image-derived name/version/CPE) so the
            // running image's real version drives CVE correlation in the fleet view.
            upsertContainerService(saved, c, observedAt);

            // Record this network's gateway for synthetic-centre upsert.
            String gwIp = primary.gatewayIp();
            if (gwIp != null && !gwIp.isBlank()) {
                gatewaysByIp.putIfAbsent(gwIp, primary.networkName());
            }
        }

        // Upsert one synthetic gateway device per docker network so the star has a real centre.
        // Gateways are DOCKER_BRIDGE-scoped so they are grouped under their Docker network zone
        // in the topology renderer. They are NOT the host node — host.docker.internal is a
        // separate HOME device seeded by the host/passive discovery path.
        List<Long> gatewayDeviceIds = new ArrayList<>();
        int gatewayCount = upsertGateways(gatewaysByIp, origin, observedAt, gatewayDeviceIds);
        deviceIds.addAll(gatewayDeviceIds);

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

    /**
     * Subnets-only network ingest: persists gateway devices for each SNMP-discovered docker
     * bridge attachment. No container rows are created — gateways only (R2/R7).
     *
     * <p>Reuses {@code source=DOCKER} and {@link DiscoveryScope#DOCKER_BRIDGE} (no new
     * DiscoverySource). Uses the synthetic {@code docker-net:*} gateway naming convention.
     *
     * <p>Intentionally NOT {@code @Transactional}: each gateway upsert commits independently.
     *
     * @param attachments gateway-only attachments from {@link io.castellum.discovery.probe.SnmpBridgeMapper}
     * @param origin      origin context (the probed host)
     * @param observedAt  the observation timestamp
     * @return a summary with containerCount=0 and gatewayCount=number of upserted gateways
     */
    public DockerDiscoveryResponse ingestNetworks(List<DockerNetworkAttachment> attachments,
                                                  OriginContext origin,
                                                  Instant observedAt) {
        // Build gatewaysByIp from attachments (skip blank or null gateway IPs)
        Map<String, String> gatewaysByIp = new LinkedHashMap<>();
        if (attachments != null) {
            for (DockerNetworkAttachment att : attachments) {
                String gwIp = att.gatewayIp();
                if (gwIp == null || gwIp.isBlank()) continue;
                // networkName stored as "snmp-bridge:<ifName>"; strip prefix for the synthetic name
                String networkName = att.networkName();
                gatewaysByIp.putIfAbsent(gwIp, networkName);
            }
        }

        List<Long> gatewayDeviceIds = new ArrayList<>();
        int gatewayCount = upsertGateways(gatewaysByIp, origin, observedAt, gatewayDeviceIds);

        auditService.recordEvent(
            "discovery",
            "DOCKER_DISCOVERY",
            "discovery",
            "docker-snmp",
            Map.of(
                "containers", 0,
                "gateways", gatewayCount,
                "updated", gatewayCount));

        log.info("SNMP bridge ingest upserted {} gateways for origin {}", gatewayCount, origin.originHostIp());
        return new DockerDiscoveryResponse(0, gatewayCount, gatewayCount, gatewayDeviceIds);
    }

    /**
     * Shared gateway upsert loop.
     * Extracted from {@link #ingest} so both the container path and the SNMP-only path
     * ({@link #ingestNetworks}) share the same logic (R2 — byte-identical gateway semantics).
     *
     * @param gatewaysByIp   map of gatewayIp → networkName
     * @param origin         origin context
     * @param observedAt     observation timestamp
     * @param deviceIds      accumulator for upserted device IDs (mutated by this method)
     * @return count of upserted gateways
     */
    private int upsertGateways(Map<String, String> gatewaysByIp,
                                OriginContext origin,
                                Instant observedAt,
                                List<Long> deviceIds) {
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
                null,
                false);                     // synthetic gateway never publishes a host port
            Device saved = upsertService.upsertWithScope(disc, DiscoveryScope.DOCKER_BRIDGE, origin);
            deviceIds.add(saved.getId());
            gatewayCount++;
        }
        return gatewayCount;
    }

    // -----------------------------------------------------------------------
    // Default-bridge segmentation detector (LOCAL discover() path only)
    // -----------------------------------------------------------------------

    /**
     * Best-effort default-bridge segmentation check. Runs {@code docker network inspect -- bridge}
     * (READ-ONLY — invariant 1), parses ICC flag + member list, and emits a posture finding on the
     * {@code docker-net:bridge} gateway device when warranted (invariant 8 port sentinel).
     *
     * <p>Any {@link DiscoveryUnavailableException} from {@link DockerCliClient#networkInspect} is
     * caught and logged; discovery never fails because of a missing network inspect (invariant 7).
     *
     * <p>Called from {@link #discover()} AFTER {@link #ingest} — the anchor device
     * ({@code docker-net:bridge} at the subnet's {@code .1}) must already exist (invariant 5).
     */
    private void checkDefaultBridge(Instant observedAt) {
        String netJson;
        try {
            netJson = cli.networkInspect("bridge");
        } catch (DiscoveryUnavailableException e) {
            // Older docker daemon, or no default bridge — skip the finding (invariant 7).
            log.info("Default-bridge segmentation check skipped (docker network inspect unavailable): {}", e.getMessage());
            return;
        }

        DockerInspectParser.BridgeNetworkInfo info = parser.parseNetworkInspect(netJson);

        if (!info.isDefaultBridge() || info.members().isEmpty()) {
            // No authoritative default bridge found, or zero containers — no finding (invariant: zero ⇒ skip).
            return;
        }

        // Derive the gateway IP from the subnet (e.g. "172.17.0.0/16" → "172.17.0.1").
        String gwIp = deriveGatewayIp(info.subnet());
        if (gwIp == null) {
            log.debug("Default-bridge: cannot derive gateway IP from subnet '{}' — skipping finding", info.subnet());
            return;
        }

        // Locate the anchor device upserted by ingest() as "docker-net:bridge".
        java.util.Optional<Device> anchorOpt =
            deviceRepository.findByIpAddressAndOriginHostIp(gwIp, "local");
        if (anchorOpt.isEmpty()) {
            log.debug("Default-bridge: no docker-net:bridge gateway at {} — skipping finding", gwIp);
            return;
        }
        Long deviceId = anchorOpt.get().getId();

        // Severity ladder (invariants 2 + 3 + 7):
        int memberCount = info.members().size();
        String severity;
        String name;
        String detail;

        if (!info.iccEnabled()) {
            // ICC disabled — lateral reach claim would be false; downgrade (invariant 2).
            severity = "INFO";
            name = "default-bridge-segmentation";
            detail = "legacy default bridge in use (inter-container communication disabled). "
                + "Prefer a user-defined network for explicit isolation and DNS.";
        } else if (memberCount == 1) {
            // Single container — no lateral-movement risk regardless of ICC.
            severity = "INFO";
            name = "default-bridge-segmentation";
            detail = "Single container on the default bridge — prefer a user-defined network for isolation + DNS.";
        } else {
            // ≥2 containers AND ICC enabled → LOW (invariant 3: "reachable", NEVER "communicating").
            severity = "LOW";
            name = "default-bridge-segmentation";
            StringBuilder sb = new StringBuilder();
            sb.append(memberCount)
              .append(" containers mutually reachable on the default bridge (no segmentation; ")
              .append("lateral-movement path): ");
            for (int i = 0; i < info.members().size(); i++) {
                if (i > 0) sb.append(", ");
                DockerInspectParser.Member m = info.members().get(i);
                sb.append(m.name()).append('(').append(m.ipv4()).append(')');
            }
            sb.append(". Remediation: isolate containers with `docker network create` + ")
              .append("`docker network connect`, or declare separate `networks:` in compose.");
            detail = sb.toString();
        }

        raiseDefaultBridgeFinding(deviceId, severity, name, detail, observedAt);
    }

    /**
     * Derive the gateway IP from a CIDR subnet string (e.g. {@code "172.17.0.0/16"} → {@code "172.17.0.1"}).
     * Returns null if the subnet is null/blank or cannot be parsed.
     *
     * <p>Package-private (not {@code private}) so {@code DeriveGatewayIpTest} in the same package
     * can exercise the octet-range guard directly without a Spring context.
     */
    static String deriveGatewayIp(String subnet) {
        if (subnet == null || subnet.isBlank()) {
            return null;
        }
        // Take the network address part (before '/'), split on '.', increment the last octet to 1.
        String addr = subnet.contains("/") ? subnet.substring(0, subnet.indexOf('/')) : subnet;
        String[] octets = addr.split("\\.", -1);
        if (octets.length != 4) {
            return null;
        }
        // For any /prefix: gateway is conventionally network_address + 1 on the host part.
        // For 172.17.0.0/16 → 172.17.0.1; for 10.0.0.0/8 → 10.0.0.1.
        try {
            int last = Integer.parseInt(octets[3]);
            // Guard: last octet must be in [0, 254] so that last+1 stays in valid octet range [1, 255].
            // A network address ending in .255 (e.g. "10.0.0.255/24") would produce the invalid
            // "10.0.0.256" without this check — return null instead.
            if (last < 0 || last > 254) {
                return null;
            }
            octets[3] = String.valueOf(last + 1);
        } catch (NumberFormatException e) {
            return null;
        }
        return String.join(".", octets);
    }

    /**
     * Upsert the default-bridge posture finding row, keyed on the sentinel
     * {@code (deviceId, DEFAULT_BRIDGE_FINDING_PORT, DEFAULT_BRIDGE_FINDING_PROTOCOL)}.
     *
     * <p>Mirrors the {@code raiseExposureFinding} shape from
     * {@link io.castellum.discovery.probe.DockerHostProbeService} — does NOT call that private
     * method directly (invariant 5). Idempotent: re-runs update the existing row in place.
     */
    private void raiseDefaultBridgeFinding(Long deviceId, String severity, String name,
                                           String detail, Instant observedAt) {
        NetworkService svc = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(deviceId, DEFAULT_BRIDGE_FINDING_PORT, DEFAULT_BRIDGE_FINDING_PROTOCOL)
            .orElseGet(NetworkService::new);
        svc.setDeviceId(deviceId);
        svc.setPort(DEFAULT_BRIDGE_FINDING_PORT);
        svc.setProtocol(DEFAULT_BRIDGE_FINDING_PROTOCOL);
        svc.setName(name);
        // The detail text rides in the version field — a free-form-text carrier reused so no schema
        // change is needed (the underlying service.version column is TEXT/unbounded, not length-capped).
        // It surfaces in the DeviceDetailPanel services table, so truncate at 255 chars to keep that
        // cell readable — this is a display bound, not a column constraint.
        svc.setVersion(detail != null && detail.length() > 255 ? detail.substring(0, 252) + "..." : detail);
        svc.setProtocolFamily(PROTOCOL_FAMILY_DEFAULT_BRIDGE_ICC);
        svc.setPostureSeverity(severity);
        svc.setObservedAt(observedAt);
        networkServiceRepository.save(svc);
    }

    /**
     * Upsert the container's primary network service, keyed on {@code (deviceId, port, protocol)}.
     *
     * <p>Name/version/CPE come from the container image via {@link DockerImageCpe#derive}. Images
     * whose base name maps to a known NVD product AND whose tag yields a concrete version (e.g.
     * {@code postgres:16}) get a version-bearing CPE so {@link io.castellum.cve.CveMatcher}
     * range-matches real CVEs; other images record an inventory-only service (name + version, no
     * CPE). Containers exposing no port, or with a blank/unparseable image, get no service row.
     *
     * <p>If an existing row already has a non-null {@code product} — meaning an nmap SERVICE_DETECT
     * run has supplied a specific fingerprint — the docker image label is NOT applied, preserving
     * the more precise identification. The {@code observedAt} timestamp is always refreshed so the
     * topology reflects the container is still running.
     */
    private void upsertContainerService(Device device, DockerContainer c, Instant observedAt) {
        DockerContainer.ExposedPort primary = c.primaryPort();
        if (primary == null) {
            return; // no listening port to key a service on
        }
        DockerImageCpe.DerivedService derived = DockerImageCpe.derive(c.image());
        if (derived == null) {
            return; // image null/blank/unparseable — nothing to record
        }
        NetworkService ns = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(device.getId(), primary.port(), primary.protocol())
            .orElseGet(NetworkService::new);
        if (ns.getId() == null) {
            ns.setDeviceId(device.getId());
            ns.setPort(primary.port());
            ns.setProtocol(primary.protocol());
        }
        // AC4: preserve a more-precise fingerprint in the existing row; only refresh timestamp.
        //
        // Case A — nmap fingerprint guard (NB-1): if the existing row has a non-null product AND
        // a non-null CPE, AND the incoming docker image would also produce a non-null CPE (i.e.
        // the image has a concrete version tag that maps to a known product), the existing CPE is
        // treated as more authoritative — nmap -sV typically yields a deeper patch version
        // (e.g. "8.0.46-1.el9") than a docker tag (e.g. "8.0"). Requiring derived.cpe() != null
        // ensures that a version-less re-tag (":latest") DOES clear stale CPE data rather than
        // locking it in place.
        if (derived.cpe() != null && ns.getProduct() != null && ns.getCpe() != null) {
            ns.setObservedAt(observedAt);
            networkServiceRepository.save(ns);
            return;
        }
        // Case B — unmapped image guard (AC4 original): docker cannot identify this service's
        // product (image base name not in curated map) but an nmap fingerprint already gave the
        // row a product. Do not overwrite the more specific identification with the generic label.
        if (derived.product() == null && ns.getProduct() != null) {
            ns.setObservedAt(observedAt);
            networkServiceRepository.save(ns);
            return;
        }
        ns.setName(derived.displayName());
        ns.setVersion(derived.version());
        ns.setProduct(derived.product());
        ns.setCpe(derived.cpe());
        ns.setObservedAt(observedAt);
        networkServiceRepository.save(ns);
    }
}
