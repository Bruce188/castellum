package io.castellum.graph;

import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
import io.castellum.discovery.DiscoveryScope;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.CompositeScorer;
import io.castellum.risk.CvssExtractor;
import io.castellum.risk.EpssScoreRepository;
import io.castellum.risk.KevEntryRepository;
import io.castellum.risk.RiskInputs;
import io.castellum.risk.RiskScore;
import org.jgrapht.Graph;
import org.jgrapht.graph.DirectedWeightedPseudograph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Builds the attack graph from the device + service + CVE corpus.
 *
 * <p>Graph type is {@link DirectedWeightedPseudograph} — JGraphT permits parallel edges
 * between the same vertex pair. The builder dedupes structurally via the {@code (srcId, tgtId, cveId)}
 * tuple through {@link Graph#addEdge(Object, Object, Object)}'s return-value contract:
 * a {@code false} return means the edge was rejected as a structural duplicate.
 *
 * <p>SAME_SUBNET edges have no {@code cveId} and naturally collapse to one per direction.
 * EXPLOITABLE_VULN edges are bounded by {@link GraphProperties#getVulnsPerPairCap()}
 * (default 5) — UI consumers (e.g. Cytoscape) MUST further dedupe presentation if they
 * collapse multi-edges into a single visual.
 *
 * <p>Subnet bucketing widens to IPv6 in feature 5: IPv4 /24 and IPv6 /64 share the same
 * {@code Map<String, List<Device>>} via the {@code v4:}/{@code v6:} prefix on the bucket key
 * returned by {@link #extractSubnetKey(String)}.
 *
 * <p>PUBLIC-scope isolation invariant (IPv4): PUBLIC devices appear as vertices but never
 * receive v4 SAME_SUBNET edges, in either direction — a shared /24 across the internet
 * implies no L2 adjacency, unlike LINK_LOCAL whose 169.254.0.0/16 adjacency is genuine
 * segment adjacency and therefore keeps its SAME_SUBNET edges. The exclusion is surgical:
 * a PUBLIC device is skipped when filling v4 subnet buckets, not the bucket dropped, so
 * co-bucketed HOME devices keep their own SAME_SUBNET edges. Starving a device of bucket
 * membership also starves it of EXPLOITABLE_VULN edges (that pass iterates sameSubnetPeers
 * only), and the GATEWAY_PIVOT pass excludes PUBLIC by construction in both address
 * families (pivots must be HOME, members must be DOCKER_BRIDGE).
 *
 * <p>IPv6 is deliberately exempt from the isolation invariant: {@code DiscoveryScopeClassifier}
 * maps every global-unicast v6 address to PUBLIC — including RA/SLAAC-assigned LAN prefixes —
 * so excluding PUBLIC from v6 buckets would sever genuinely L2-adjacent v6 LAN devices.
 * Sharing a /64 is itself strong same-link evidence, so v6 /64 bucketing remains scope-blind
 * and PUBLIC v6 devices keep SAME_SUBNET (and consequent EXPLOITABLE_VULN) adjacency.
 *
 * <p>A third, additive gateway-bridge pass runs after the EXPLOITABLE_VULN pass. DOCKER_BRIDGE
 * devices are partitioned by {@code originHostIp}. For each partition a pivot HOME device is
 * resolved: the {@code "local"} origin matches the configured
 * {@link GraphProperties#getDockerHostIp()}; non-local origins match a HOME device whose
 * {@code ipAddress} equals the origin host IP. Bidirectional {@link EdgeType#GATEWAY_PIVOT}
 * edges are emitted ONLY between the pivot and members of its own partition — cross-origin
 * bridging never occurs. Pivot detection is IP-based only — the hostname alias
 * {@code "host.docker.internal"} is a Docker network artifact, never stored as a real hostname.
 * LINK_LOCAL and LOOPBACK scopes are explicitly excluded. Single-origin ({@code "local"}) input
 * is byte-identical to the prior single-pivot behaviour. When no pivot is detected for a
 * partition, that partition's DOCKER_BRIDGE devices remain isolated.
 */
@Component
public class GraphBuilder {

    private static final Logger log = LoggerFactory.getLogger(GraphBuilder.class);

    private final DeviceRepository deviceRepository;
    private final NetworkServiceRepository networkServiceRepository;
    private final CveMatcher cveMatcher;
    private final EpssScoreRepository epssScoreRepository;
    private final KevEntryRepository kevEntryRepository;
    private final GraphProperties properties;

    public GraphBuilder(DeviceRepository deviceRepository,
                        NetworkServiceRepository networkServiceRepository,
                        CveMatcher cveMatcher,
                        EpssScoreRepository epssScoreRepository,
                        KevEntryRepository kevEntryRepository,
                        GraphProperties properties) {
        this.deviceRepository = deviceRepository;
        this.networkServiceRepository = networkServiceRepository;
        this.cveMatcher = cveMatcher;
        this.epssScoreRepository = epssScoreRepository;
        this.kevEntryRepository = kevEntryRepository;
        this.properties = properties;
    }

    public BuiltGraph build() {
        Graph<DeviceVertex, AttackEdge> graph =
            new DirectedWeightedPseudograph<>(AttackEdge.class);

        List<Device> devices = deviceRepository.findAll();
        if (devices.size() > properties.getMaxDevices()) {
            throw new GraphTooLargeException(devices.size(), properties.getMaxDevices());
        }
        Map<Long, DeviceVertex> vertexById = new HashMap<>();
        for (Device d : devices) {
            DeviceVertex v = new DeviceVertex(d.getId(), d.getIpAddress());
            graph.addVertex(v);
            vertexById.put(d.getId(), v);
        }

        // SAME_SUBNET pass — IPv4 /24 and IPv6 /64 share the same bucket map.
        // PUBLIC-scope devices are excluded from the IPv4 buckets ONLY (and not the
        // buckets dropped): a shared /24 across the public internet implies no L2
        // adjacency, so v4 PUBLIC never gets SAME_SUBNET edges — and, because the
        // EXPLOITABLE_VULN pass draws exclusively on sameSubnetPeers, no
        // EXPLOITABLE_VULN edges either. IPv6 stays scope-blind: the classifier maps
        // every global-unicast v6 address to PUBLIC (RA/SLAAC LAN prefixes included),
        // while a shared /64 is strong same-link evidence — excluding PUBLIC there
        // would sever genuinely L2-adjacent v6 LAN devices. Remaining devices in the
        // same bucket keep their adjacency untouched.
        Map<String, List<Device>> bySubnet = new LinkedHashMap<>();
        for (Device d : devices) {
            String prefix = extractSubnetKey(d.getIpAddress());
            if (prefix == null) continue;
            if (d.getDiscoveryScope() == DiscoveryScope.PUBLIC && prefix.startsWith("v4:")) continue;
            bySubnet.computeIfAbsent(prefix, k -> new ArrayList<>()).add(d);
        }
        Map<Long, List<Long>> sameSubnetPeers = new HashMap<>();
        for (Map.Entry<String, List<Device>> e : bySubnet.entrySet()) {
            List<Device> group = e.getValue();
            if (group.size() > properties.getSubnetCap()) {
                log.warn("subnet {} has {} devices, exceeds subnet-cap={}; skipping SAME_SUBNET edges",
                    e.getKey(), group.size(), properties.getSubnetCap());
                continue;
            }
            for (Device a : group) {
                for (Device b : group) {
                    if (a.getId().equals(b.getId())) continue;
                    DeviceVertex va = vertexById.get(a.getId());
                    DeviceVertex vb = vertexById.get(b.getId());
                    AttackEdge edge = new AttackEdge(EdgeType.SAME_SUBNET,
                        EdgeWeights.sameSubnetRisk(), null, null);
                    if (graph.addEdge(va, vb, edge)) {
                        graph.setEdgeWeight(edge, EdgeWeights.sameSubnetWeight());
                        sameSubnetPeers.computeIfAbsent(b.getId(), k -> new ArrayList<>()).add(a.getId());
                    }
                }
            }
        }

        // EXPLOITABLE_VULN pass — helper-class consolidation: CpeMapper, CompositeScoreMemoizer,
        // EdgeWeights, AttackTechniqueMapper.
        CompositeScoreMemoizer memo = new CompositeScoreMemoizer();
        for (Device d : devices) {
            // Edges from this pass land only between a device and its same-subnet
            // peers, so a device with no inbound peers (v4 PUBLIC, singleton subnet,
            // capped bucket) can skip the service-fetch + CVE-match + scoring work
            // entirely — it would all be discarded below.
            List<Long> peers = sameSubnetPeers.getOrDefault(d.getId(), List.of());
            if (peers.isEmpty()) continue;
            List<NetworkService> services = networkServiceRepository.findByDeviceId(d.getId());
            // Collect all matched (cve, score, service) triples, then take top-N by composite score.
            List<ScoredCve> scored = new ArrayList<>();
            for (NetworkService svc : services) {
                if (svc.getName() == null || svc.getName().isBlank()) continue;
                String cpe23 = CpeMapper.toCpe23(svc);
                if (cpe23 == null) continue;
                List<Cve> cves = cveMatcher.findVulnerable(cpe23);
                for (Cve cve : cves) {
                    final Device target = d;
                    RiskScore score = memo.computeIfAbsent(cve.getCveId(), d.getId(),
                        () -> CompositeScorer.score(new RiskInputs(
                            CvssExtractor.normalized(cve),
                            epssScoreRepository.findByCveId(cve.getCveId())
                                .map(es -> es.getEpss().doubleValue())
                                .orElse(0.0),
                            kevEntryRepository.existsByCveId(cve.getCveId()),
                            target.getCriticality())));
                    scored.add(new ScoredCve(cve, score, svc));
                }
            }
            if (scored.isEmpty()) continue;
            scored.sort(Comparator.comparing((ScoredCve s) -> s.score().score()).reversed());
            int cap = Math.min(scored.size(), properties.getVulnsPerPairCap());
            List<ScoredCve> top = scored.subList(0, cap);

            DeviceVertex vd = vertexById.get(d.getId());
            for (Long peerId : peers) {
                DeviceVertex vs = vertexById.get(peerId);
                for (ScoredCve sc : top) {
                    String techniqueId = AttackTechniqueMapper
                        .forEdgeType(EdgeType.EXPLOITABLE_VULN, sc.service()).id();
                    AttackEdge edge = new AttackEdge(EdgeType.EXPLOITABLE_VULN,
                        EdgeWeights.exploitableVulnRisk(sc.score()),
                        sc.cve().getCveId(), techniqueId);
                    if (graph.addEdge(vs, vd, edge)) {
                        graph.setEdgeWeight(edge, EdgeWeights.exploitableVulnWeight(sc.score()));
                    }
                }
            }
        }

        // WEAK_CRED_PATH: typed-but-empty seam — no signal source in v1; see analysis-v5 § 3.

        // GATEWAY_PIVOT pass — bridges HOME and DOCKER_BRIDGE scopes through per-origin pivot nodes.
        // Pivot detection is per-origin: DOCKER_BRIDGE devices are partitioned by originHostIp.
        // For each partition, the pivot HOME device is resolved:
        //   - origin "local" → HOME device whose IP matches the configured dockerHostIp (min by id).
        //   - non-local origin → HOME device whose ipAddress equals that originHostIp (min by id).
        // GATEWAY_PIVOT edges are emitted ONLY between the pivot and members of its own partition.
        // Single-origin ("local") input reproduces the previous single-pivot loop byte-identically.
        // Hostname is deliberately NOT used — "host.docker.internal" is filtered by DeviceUpsertService.
        // LINK_LOCAL and LOOPBACK scopes are never bridged by this pass.

        // Partition DOCKER_BRIDGE devices by originHostIp (LinkedHashMap for determinism).
        Map<String, List<Device>> dockerByOrigin = new LinkedHashMap<>();
        for (Device d : devices) {
            if (d.getDiscoveryScope() != DiscoveryScope.DOCKER_BRIDGE) continue;
            String origin = d.getOriginHostIp() != null ? d.getOriginHostIp() : "local";
            dockerByOrigin.computeIfAbsent(origin, k -> new ArrayList<>()).add(d);
        }

        String techniqueId = AttackTechniqueMapper.forEdgeType(EdgeType.GATEWAY_PIVOT).id();
        for (Map.Entry<String, List<Device>> entry : dockerByOrigin.entrySet()) {
            String originHostIp = entry.getKey();
            List<Device> dockerMembers = entry.getValue();

            // Resolve the pivot HOME device for this partition.
            Device pivot;
            if ("local".equals(originHostIp)) {
                // Local origin: match by configured dockerHostIp.
                pivot = devices.stream()
                    .filter(d -> d.getDiscoveryScope() == DiscoveryScope.HOME)
                    .filter(d -> properties.getDockerHostIp().equals(d.getIpAddress()))
                    .min(Comparator.comparingLong(Device::getId))
                    .orElse(null);
            } else {
                // Remote origin: HOME device whose IP equals the origin host IP.
                pivot = devices.stream()
                    .filter(d -> d.getDiscoveryScope() == DiscoveryScope.HOME)
                    .filter(d -> originHostIp.equals(d.getIpAddress()))
                    .min(Comparator.comparingLong(Device::getId))
                    .orElse(null);
            }

            if (pivot == null) continue;

            if (dockerMembers.size() > properties.getSubnetCap()) {
                log.warn("docker-bridge partition for origin {} has {} members, exceeds subnet-cap={}; skipping GATEWAY_PIVOT edges",
                    originHostIp, dockerMembers.size(), properties.getSubnetCap());
                continue;
            }

            DeviceVertex vPivot = vertexById.get(pivot.getId());
            for (Device member : dockerMembers) {
                DeviceVertex vMember = vertexById.get(member.getId());
                AttackEdge fwd = new AttackEdge(EdgeType.GATEWAY_PIVOT,
                    EdgeWeights.gatewayPivotRisk(), null, techniqueId);
                if (graph.addEdge(vPivot, vMember, fwd)) {
                    graph.setEdgeWeight(fwd, EdgeWeights.gatewayPivotWeight());
                }
                AttackEdge rev = new AttackEdge(EdgeType.GATEWAY_PIVOT,
                    EdgeWeights.gatewayPivotRisk(), null, techniqueId);
                if (graph.addEdge(vMember, vPivot, rev)) {
                    graph.setEdgeWeight(rev, EdgeWeights.gatewayPivotWeight());
                }
            }
        }

        return new BuiltGraph(graph, Map.copyOf(vertexById));
    }

    /**
     * Bucket key for SAME_SUBNET grouping. Returns {@code "v4:a.b.c"} for an IPv4 /24 prefix or
     * {@code "v6:h:h:h:h"} for an IPv6 /64 prefix (lowercase hextets). Returns {@code null} on
     * parse failure or unexpected family — the caller must skip such devices.
     */
    static String extractSubnetKey(String ip) {
        if (ip == null) return null;
        try {
            InetAddress addr = InetAddress.getByName(ip);
            if (addr instanceof Inet4Address v4) {
                byte[] b = v4.getAddress();
                return "v4:" + (b[0] & 0xff) + "." + (b[1] & 0xff) + "." + (b[2] & 0xff);
            } else if (addr instanceof Inet6Address v6) {
                byte[] b = v6.getAddress();
                // /64 = first 8 bytes; emit as colon-separated hextets.
                return String.format(Locale.ROOT, "v6:%x:%x:%x:%x",
                    ((b[0] & 0xff) << 8) | (b[1] & 0xff),
                    ((b[2] & 0xff) << 8) | (b[3] & 0xff),
                    ((b[4] & 0xff) << 8) | (b[5] & 0xff),
                    ((b[6] & 0xff) << 8) | (b[7] & 0xff));
            }
            return null;
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private record ScoredCve(Cve cve, RiskScore score, NetworkService service) {}
}
