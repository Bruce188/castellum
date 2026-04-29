package io.castellum.graph;

import io.castellum.cve.Cve;
import io.castellum.cve.CveMatcher;
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

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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

    public Graph<DeviceVertex, AttackEdge> build() {
        Graph<DeviceVertex, AttackEdge> graph =
            new DirectedWeightedPseudograph<>(AttackEdge.class);

        List<Device> devices = deviceRepository.findAll();
        Map<Long, DeviceVertex> vertexById = new HashMap<>();
        for (Device d : devices) {
            DeviceVertex v = new DeviceVertex(d.getId(), d.getIpAddress());
            graph.addVertex(v);
            vertexById.put(d.getId(), v);
        }

        // SAME_SUBNET pass.
        Map<String, List<Device>> bySubnet = new LinkedHashMap<>();
        for (Device d : devices) {
            String prefix = extractIpv4Prefix24(d.getIpAddress());
            if (prefix == null) continue;
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
                    AttackEdge edge = new AttackEdge(EdgeType.SAME_SUBNET, 0.0, null);
                    if (graph.addEdge(va, vb, edge)) {
                        graph.setEdgeWeight(edge, 1.0);
                        sameSubnetPeers.computeIfAbsent(b.getId(), k -> new ArrayList<>()).add(a.getId());
                    }
                }
            }
        }

        // EXPLOITABLE_VULN pass.
        BuildContext ctx = new BuildContext();
        for (Device d : devices) {
            List<NetworkService> services = networkServiceRepository.findByDeviceId(d.getId());
            // Collect all matched (cve, composite) pairs, then take top-N.
            List<ScoredCve> scored = new ArrayList<>();
            for (NetworkService svc : services) {
                if (svc.getName() == null || svc.getName().isBlank()) continue;
                String cpe23 = buildCpe(svc);
                List<Cve> cves = cveMatcher.findVulnerable(cpe23);
                for (Cve cve : cves) {
                    BigDecimal composite = ctx.compositeFor(cve, d);
                    scored.add(new ScoredCve(cve, composite));
                }
            }
            if (scored.isEmpty()) continue;
            scored.sort(Comparator.comparing((ScoredCve s) -> s.composite()).reversed());
            int cap = Math.min(scored.size(), properties.getVulnsPerPairCap());
            List<ScoredCve> top = scored.subList(0, cap);

            DeviceVertex vd = vertexById.get(d.getId());
            List<Long> peers = sameSubnetPeers.getOrDefault(d.getId(), List.of());
            for (Long peerId : peers) {
                DeviceVertex vs = vertexById.get(peerId);
                for (ScoredCve sc : top) {
                    double cs = sc.composite().doubleValue();
                    AttackEdge edge = new AttackEdge(EdgeType.EXPLOITABLE_VULN, cs, sc.cve().getCveId());
                    if (graph.addEdge(vs, vd, edge)) {
                        graph.setEdgeWeight(edge, 11.0 - cs);
                    }
                }
            }
        }

        // WEAK_CRED_PATH: typed-but-empty seam — no signal source in v1; see analysis-v5 § 3.

        return graph;
    }

    static String extractIpv4Prefix24(String ip) {
        if (ip == null) return null;
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return null;
        for (String p : parts) {
            try {
                int v = Integer.parseInt(p);
                if (v < 0 || v > 255) return null;
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return parts[0] + "." + parts[1] + "." + parts[2];
    }

    private static String buildCpe(NetworkService svc) {
        String sanitized = sanitize(svc.getName());
        String version = svc.getVersion() != null ? svc.getVersion() : "*";
        return "cpe:2.3:a:" + sanitized + ":" + sanitized + ":" + version + ":*:*:*:*:*:*:*";
    }

    private static String sanitize(String s) {
        return s.toLowerCase().replaceAll("[^a-z0-9_-]", "");
    }

    /** Per-build memoization so the same (cveId, deviceId) is computed once. */
    private final class BuildContext {
        private final Map<MemoKey, BigDecimal> cache = new HashMap<>();

        BigDecimal compositeFor(Cve cve, Device d) {
            MemoKey key = new MemoKey(cve.getCveId(), d.getId());
            BigDecimal cached = cache.get(key);
            if (cached != null) return cached;
            double cvssN = CvssExtractor.normalized(cve);
            double epss = epssScoreRepository.findByCveId(cve.getCveId())
                .map(e -> e.getEpss().doubleValue())
                .orElse(0.0);
            boolean kev = kevEntryRepository.existsByCveId(cve.getCveId());
            RiskScore score = CompositeScorer.score(new RiskInputs(cvssN, epss, kev, d.getCriticality()));
            cache.put(key, score.score());
            return score.score();
        }
    }

    private record MemoKey(String cveId, long deviceId) {}

    private record ScoredCve(Cve cve, BigDecimal composite) {}
}
