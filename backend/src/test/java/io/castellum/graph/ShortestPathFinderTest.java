package io.castellum.graph;

import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.graph.DirectedWeightedPseudograph;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ShortestPathFinderTest {

    private final ShortestPathFinder finder = new ShortestPathFinder();

    private static Graph<DeviceVertex, AttackEdge> emptyGraph() {
        return new DirectedWeightedPseudograph<>(AttackEdge.class);
    }

    @Test
    void straightPathReturnsCorrectHopOrder() {
        Graph<DeviceVertex, AttackEdge> g = emptyGraph();
        DeviceVertex a = new DeviceVertex(1L, "10.0.0.1");
        DeviceVertex b = new DeviceVertex(2L, "10.0.0.2");
        DeviceVertex c = new DeviceVertex(3L, "10.0.0.3");
        g.addVertex(a); g.addVertex(b); g.addVertex(c);
        AttackEdge ab = new AttackEdge(EdgeType.SAME_SUBNET, 0.0, null);
        AttackEdge bc = new AttackEdge(EdgeType.SAME_SUBNET, 0.0, null);
        g.addEdge(a, b, ab); g.setEdgeWeight(ab, 1.0);
        g.addEdge(b, c, bc); g.setEdgeWeight(bc, 1.0);

        Optional<GraphPath<DeviceVertex, AttackEdge>> p = finder.findPath(g, a, c);
        assertThat(p).isPresent();
        assertThat(p.get().getEdgeList()).containsExactly(ab, bc);
    }

    @Test
    void noPathReturnsEmptyOptional() {
        Graph<DeviceVertex, AttackEdge> g = emptyGraph();
        DeviceVertex a = new DeviceVertex(1L, "10.0.0.1");
        DeviceVertex c = new DeviceVertex(3L, "10.0.0.3");
        g.addVertex(a); g.addVertex(c);

        Optional<GraphPath<DeviceVertex, AttackEdge>> p = finder.findPath(g, a, c);
        assertThat(p).isEmpty();
    }

    @Test
    void cumulativeRiskAccumulatesAcrossHops() {
        Graph<DeviceVertex, AttackEdge> g = emptyGraph();
        DeviceVertex a = new DeviceVertex(1L, "10.0.0.1");
        DeviceVertex b = new DeviceVertex(2L, "10.0.0.2");
        DeviceVertex c = new DeviceVertex(3L, "10.0.0.3");
        g.addVertex(a); g.addVertex(b); g.addVertex(c);
        AttackEdge ab = new AttackEdge(EdgeType.EXPLOITABLE_VULN, 7.0, "CVE-A");
        AttackEdge bc = new AttackEdge(EdgeType.EXPLOITABLE_VULN, 8.0, "CVE-B");
        g.addEdge(a, b, ab); g.setEdgeWeight(ab, 4.0);
        g.addEdge(b, c, bc); g.setEdgeWeight(bc, 3.0);

        Optional<GraphPath<DeviceVertex, AttackEdge>> p = finder.findPath(g, a, c);
        assertThat(p).isPresent();
        double cumulative = p.get().getEdgeList().stream()
            .mapToDouble(AttackEdge::getRiskContribution).sum();
        assertThat(cumulative).isEqualTo(15.0);
    }

    @Test
    void dijkstraPicksLowerWeightPath() {
        Graph<DeviceVertex, AttackEdge> g = emptyGraph();
        DeviceVertex a = new DeviceVertex(1L, "10.0.0.1");
        DeviceVertex b = new DeviceVertex(2L, "10.0.0.2");
        DeviceVertex c = new DeviceVertex(3L, "10.0.0.3");
        g.addVertex(a); g.addVertex(b); g.addVertex(c);
        AttackEdge cheap = new AttackEdge(EdgeType.SAME_SUBNET, 0.0, null);
        AttackEdge expensive = new AttackEdge(EdgeType.EXPLOITABLE_VULN, 5.0, "CVE-X");
        g.addEdge(a, c, cheap); g.setEdgeWeight(cheap, 1.0);
        g.addEdge(a, b, expensive); g.setEdgeWeight(expensive, 5.0);
        AttackEdge bc = new AttackEdge(EdgeType.SAME_SUBNET, 0.0, null);
        g.addEdge(b, c, bc); g.setEdgeWeight(bc, 1.0);

        Optional<GraphPath<DeviceVertex, AttackEdge>> p = finder.findPath(g, a, c);
        assertThat(p).isPresent();
        assertThat(p.get().getEdgeList()).containsExactly(cheap);
    }
}
