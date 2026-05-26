package io.castellum.graph;

import io.castellum.audit.AuditService;
import io.castellum.domain.DeviceRepository;
import io.castellum.graph.dto.HopDto;
import io.castellum.graph.dto.ShortestPathResponse;
import org.jgrapht.GraphPath;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

@Service
public class GraphService {

    private static final BigDecimal ZERO = BigDecimal.ZERO.setScale(2);

    private final GraphBuilder graphBuilder;
    private final ShortestPathFinder shortestPathFinder;
    private final DeviceRepository deviceRepository;
    @SuppressWarnings("unused")
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

        BuiltGraph built = graphBuilder.build();
        DeviceVertex fromVertex = built.vertexById().get(fromId);
        DeviceVertex toVertex = built.vertexById().get(toId);
        if (fromVertex == null) throw new NoSuchElementException("device not found in graph: " + fromId);
        if (toVertex == null) throw new NoSuchElementException("device not found in graph: " + toId);

        Optional<GraphPath<DeviceVertex, AttackEdge>> path =
            shortestPathFinder.findPath(built.graph(), fromVertex, toVertex);

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
                DeviceVertex dest = built.graph().getEdgeTarget(edge);
                // Prefer the per-edge technique id captured by GraphBuilder (service-aware,
                // e.g. T1210 for SMB/RPC/RDP/SSH on EXPLOITABLE_VULN). Fall back to the
                // EdgeType-only mapping only if the edge has no captured id (defensive).
                String techId = edge.getTechniqueId();
                String techName;
                if (techId != null) {
                    techName = AttackTechniqueMapper.nameFor(techId, edge.getType());
                } else {
                    AttackTechnique tech = AttackTechniqueMapper.forEdgeType(edge.getType());
                    techId = tech.id();
                    techName = tech.name();
                }
                BigDecimal edgeRisk = round2(edge.getRiskContribution());
                cumulative = round2(cumulative.doubleValue() + edge.getRiskContribution());
                hops.add(new HopDto(dest.deviceId(), dest.ipAddress(), edge.getType(),
                    techId, techName, edgeRisk, cumulative, edge.getCveId()));
            }
            response = new ShortestPathResponse(fromId, toId, hops, path.get().getEdgeList().size(),
                cumulative, true);
        }

        return response;
    }

    private static BigDecimal round2(double v) {
        return BigDecimal.valueOf(v).setScale(2, RoundingMode.HALF_UP);
    }
}
