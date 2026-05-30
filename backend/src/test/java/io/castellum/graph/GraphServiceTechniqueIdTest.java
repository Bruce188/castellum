package io.castellum.graph;

import io.castellum.audit.AuditService;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.graph.dto.HopDto;
import io.castellum.graph.dto.ShortestPathResponse;
import io.castellum.risk.Criticality;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.graph.DirectedWeightedPseudograph;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * AC#2 REST-surface contract: the {@code attackTechniqueId} surfaced in
 * {@link ShortestPathResponse} hops must reflect the per-edge captured technique id
 * on {@link AttackEdge#getTechniqueId()} (set by {@code GraphBuilder} at build time),
 * NOT a re-mapping via {@link AttackTechniqueMapper#forEdgeType(EdgeType)}.
 *
 * <p>Tested at the {@link GraphService} unit level because the in-graph weight model
 * (SAME_SUBNET weight 1.0 ≤ EXPLOITABLE_VULN min weight 1.0) makes a Dijkstra path that
 * actually traverses an EXPLOITABLE_VULN edge unreachable end-to-end through the public
 * REST surface in the current model — see analysis-v15 D1=R / documentation/attack-graph.html
 * § "Acceptance test note". This test mocks the {@link ShortestPathFinder} so the response
 * builder is exercised over an EXPLOITABLE_VULN edge directly, proving the field is read.
 */
class GraphServiceTechniqueIdTest {

    @Test
    void shortestPath_surfacesT1210FromEdge_forSshExploitableVuln() {
        // EXPLOITABLE_VULN edge whose service-aware techniqueId is T1210 (SSH).
        ShortestPathResponse response = runWithSyntheticPath(
            EdgeType.EXPLOITABLE_VULN, "T1210", "CVE-2020-15778");

        assertThat(response.pathFound()).isTrue();
        assertThat(response.hops()).hasSize(2);
        HopDto vulnHop = response.hops().get(1);
        assertThat(vulnHop.edgeType()).isEqualTo(EdgeType.EXPLOITABLE_VULN);
        assertThat(vulnHop.attackTechniqueId()).isEqualTo("T1210");
        assertThat(vulnHop.attackTechniqueName()).isEqualTo("Exploitation of Remote Services");
        assertThat(vulnHop.cveId()).isEqualTo("CVE-2020-15778");
    }

    @Test
    void shortestPath_surfacesT1190FromEdge_forNonRemoteServiceExploitableVuln() {
        // EXPLOITABLE_VULN edge whose techniqueId is the default T1190 (e.g. nginx/HTTP).
        ShortestPathResponse response = runWithSyntheticPath(
            EdgeType.EXPLOITABLE_VULN, "T1190", "CVE-2021-23017");

        assertThat(response.pathFound()).isTrue();
        HopDto vulnHop = response.hops().get(1);
        assertThat(vulnHop.edgeType()).isEqualTo(EdgeType.EXPLOITABLE_VULN);
        assertThat(vulnHop.attackTechniqueId()).isEqualTo("T1190");
        assertThat(vulnHop.attackTechniqueName()).isEqualTo("Exploit Public-Facing Application");
    }

    @Test
    void shortestPath_fallsBackToEdgeTypeMapping_whenTechniqueIdIsNull() {
        // Defensive fallback: SAME_SUBNET edges carry no techniqueId in the current model.
        ShortestPathResponse response = runWithSyntheticPath(
            EdgeType.SAME_SUBNET, null, null);

        assertThat(response.pathFound()).isTrue();
        HopDto hop = response.hops().get(1);
        assertThat(hop.edgeType()).isEqualTo(EdgeType.SAME_SUBNET);
        assertThat(hop.attackTechniqueId()).isEqualTo("T1021");
        assertThat(hop.attackTechniqueName()).isEqualTo("Remote Services");
    }

    /**
     * Build a synthetic graph with a single edge of the given (type, techniqueId, cveId), wire
     * it into a mocked {@link GraphBuilder} + {@link ShortestPathFinder}, and invoke
     * {@link GraphService#shortestPath(long, long)}.
     */
    private ShortestPathResponse runWithSyntheticPath(EdgeType type, String techniqueId, String cveId) {
        GraphBuilder builder = mock(GraphBuilder.class);
        ShortestPathFinder finder = mock(ShortestPathFinder.class);
        DeviceRepository deviceRepo = mock(DeviceRepository.class);
        AuditService audit = mock(AuditService.class);

        Device fromDev = new Device(1L, "10.0.0.10", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.HIGH);
        Device toDev = new Device(2L, "10.0.0.20", null, null, Instant.EPOCH, Instant.EPOCH, Criticality.HIGH);
        when(deviceRepo.findById(1L)).thenReturn(Optional.of(fromDev));
        when(deviceRepo.findById(2L)).thenReturn(Optional.of(toDev));

        DeviceVertex vFrom = new DeviceVertex(1L, "10.0.0.10");
        DeviceVertex vTo = new DeviceVertex(2L, "10.0.0.20");
        Graph<DeviceVertex, AttackEdge> graph = new DirectedWeightedPseudograph<>(AttackEdge.class);
        graph.addVertex(vFrom);
        graph.addVertex(vTo);
        AttackEdge edge = new AttackEdge(type, 5.0, cveId, techniqueId);
        graph.addEdge(vFrom, vTo, edge);
        graph.setEdgeWeight(edge, 1.5);

        Map<Long, DeviceVertex> vertexById = new HashMap<>();
        vertexById.put(1L, vFrom);
        vertexById.put(2L, vTo);
        BuiltGraph built = new BuiltGraph(graph, vertexById);
        when(builder.build()).thenReturn(built);

        @SuppressWarnings("unchecked")
        GraphPath<DeviceVertex, AttackEdge> path = mock(GraphPath.class);
        when(path.getEdgeList()).thenReturn(List.of(edge));
        when(finder.findPath(graph, vFrom, vTo)).thenReturn(Optional.of(path));

        GraphService service = new GraphService(builder, finder, deviceRepo, audit);
        return service.shortestPath(1L, 2L);
    }
}
