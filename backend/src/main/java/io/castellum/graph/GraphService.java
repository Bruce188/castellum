package io.castellum.graph;

import io.castellum.audit.AuditService;
import io.castellum.domain.DeviceRepository;
import io.castellum.graph.dto.HopDto;
import io.castellum.graph.dto.ShortestPathResponse;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

@Service
public class GraphService {

    private static final BigDecimal ZERO = BigDecimal.ZERO.setScale(2);

    private final GraphBuilder graphBuilder;
    private final ShortestPathFinder shortestPathFinder;
    private final DeviceRepository deviceRepository;
    private final AuditService auditService;

    public GraphService(GraphBuilder graphBuilder,
                        ShortestPathFinder shortestPathFinder,
                        DeviceRepository deviceRepository,
                        AuditService auditService) {
        this.graphBuilder = graphBuilder;
        this.shortestPathFinder = shortestPathFinder;
        this.deviceRepository = deviceRepository;
        this.auditService = auditService;
    }

    public ShortestPathResponse shortestPath(long fromId, long toId) {
        if (fromId <= 0 || toId <= 0) throw new IllegalArgumentException("from/to must be positive");
        if (fromId == toId) throw new IllegalArgumentException("from must differ from to");

        deviceRepository.findById(fromId)
            .orElseThrow(() -> new NoSuchElementException("device not found: " + fromId));
        deviceRepository.findById(toId)
            .orElseThrow(() -> new NoSuchElementException("device not found: " + toId));

        Graph<DeviceVertex, AttackEdge> graph = graphBuilder.build();

        DeviceVertex fromVertex = findVertex(graph, fromId);
        DeviceVertex toVertex = findVertex(graph, toId);

        Optional<GraphPath<DeviceVertex, AttackEdge>> path =
            shortestPathFinder.findPath(graph, fromVertex, toVertex);

        ShortestPathResponse response;
        if (path.isEmpty()) {
            response = new ShortestPathResponse(fromId, toId, List.of(), 0, ZERO, false);
        } else {
            List<HopDto> hops = new ArrayList<>();
            // First hop = source vertex; null edge fields.
            hops.add(new HopDto(fromVertex.deviceId(), fromVertex.ipAddress(), null, null, null,
                ZERO, ZERO, null));
            BigDecimal cumulative = ZERO;
            for (AttackEdge edge : path.get().getEdgeList()) {
                DeviceVertex dest = graph.getEdgeTarget(edge);
                AttackTechnique tech = AttackTechniqueMapper.forEdgeType(edge.getType());
                BigDecimal edgeRisk = round2(edge.getRiskContribution());
                cumulative = round2(cumulative.doubleValue() + edge.getRiskContribution());
                hops.add(new HopDto(dest.deviceId(), dest.ipAddress(), edge.getType(),
                    tech.id(), tech.name(), edgeRisk, cumulative, edge.getCveId()));
            }
            response = new ShortestPathResponse(fromId, toId, hops, path.get().getEdgeList().size(),
                cumulative, true);
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("from", fromId);
        payload.put("to", toId);
        payload.put("totalHops", response.totalHops());
        payload.put("cumulativeRisk", response.cumulativeRisk());
        auditService.recordEvent("graph", "GRAPH_QUERY", "graph",
            fromId + "-" + toId, payload);

        return response;
    }

    private static DeviceVertex findVertex(Graph<DeviceVertex, AttackEdge> graph, long deviceId) {
        for (DeviceVertex v : graph.vertexSet()) {
            if (v.deviceId() == deviceId) return v;
        }
        throw new NoSuchElementException("device not found in graph: " + deviceId);
    }

    private static BigDecimal round2(double v) {
        return BigDecimal.valueOf(v).setScale(2, RoundingMode.HALF_UP);
    }
}
