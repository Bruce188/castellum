package io.castellum.graph;

import io.castellum.audit.AuditService;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.risk.Criticality;
import org.jgrapht.Graph;
import org.jgrapht.graph.DirectedWeightedPseudograph;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Phase C — guards against re-introducing the O(|V|) findVertex(graph, id) scan.
 * GraphService.shortestPath must resolve both endpoints via BuiltGraph.vertexById().get(...)
 * — i.e. exactly one Map#get per endpoint, zero iteration of vertexSet.
 */
class GraphServiceVertexLookupTest {

    @Test
    void shortestPath_callsBuiltGraphVertexByIdGetExactlyTwicePerRequest() {
        GraphBuilder builder = mock(GraphBuilder.class);
        ShortestPathFinder finder = mock(ShortestPathFinder.class);
        DeviceRepository deviceRepo = mock(DeviceRepository.class);
        AuditService audit = mock(AuditService.class);

        Device fromDev = device(1L, "10.0.0.10");
        Device toDev = device(2L, "10.0.0.20");
        when(deviceRepo.findById(1L)).thenReturn(Optional.of(fromDev));
        when(deviceRepo.findById(2L)).thenReturn(Optional.of(toDev));

        DeviceVertex vFrom = new DeviceVertex(1L, "10.0.0.10");
        DeviceVertex vTo = new DeviceVertex(2L, "10.0.0.20");
        Graph<DeviceVertex, AttackEdge> graph = new DirectedWeightedPseudograph<>(AttackEdge.class);
        graph.addVertex(vFrom);
        graph.addVertex(vTo);

        CountingMap<Long, DeviceVertex> counting = new CountingMap<>();
        counting.put(1L, vFrom);
        counting.put(2L, vTo);
        BuiltGraph built = new BuiltGraph(graph, counting);
        when(builder.build()).thenReturn(built);
        when(finder.findPath(graph, vFrom, vTo)).thenReturn(Optional.empty());

        GraphService service = new GraphService(builder, finder, deviceRepo, audit);
        service.shortestPath(1L, 2L);

        assertThat(counting.gets()).isEqualTo(2);
    }

    @Test
    void shortestPath_doesNotIterateGraphVertexSetOnLookup() {
        // If any future regression reintroduces vertexSet() scanning, this test fails:
        // we wrap the graph in a spy that counts vertexSet() invocations during the
        // shortestPath call and assert it was never called by the lookup path.
        GraphBuilder builder = mock(GraphBuilder.class);
        ShortestPathFinder finder = mock(ShortestPathFinder.class);
        DeviceRepository deviceRepo = mock(DeviceRepository.class);
        AuditService audit = mock(AuditService.class);

        when(deviceRepo.findById(anyLong())).thenAnswer(inv -> Optional.of(device(inv.getArgument(0), "10.0.0.1")));

        DeviceVertex vFrom = new DeviceVertex(1L, "10.0.0.10");
        DeviceVertex vTo = new DeviceVertex(2L, "10.0.0.20");
        VertexSetCountingGraph graph = new VertexSetCountingGraph();
        graph.addVertex(vFrom);
        graph.addVertex(vTo);

        Map<Long, DeviceVertex> map = new HashMap<>();
        map.put(1L, vFrom);
        map.put(2L, vTo);
        when(builder.build()).thenReturn(new BuiltGraph(graph, map));
        when(finder.findPath(graph, vFrom, vTo)).thenReturn(Optional.empty());

        GraphService service = new GraphService(builder, finder, deviceRepo, audit);
        int before = graph.vertexSetCalls();
        service.shortestPath(1L, 2L);
        int after = graph.vertexSetCalls();
        // Auditing or response shaping may not call vertexSet at all — the key is that
        // lookup of from/to does not. Guard the delta is zero.
        assertThat(after - before).isEqualTo(0);
    }

    private static Device device(long id, String ip) {
        return new Device(id, ip, null, null, Instant.EPOCH, Instant.EPOCH, Criticality.MEDIUM);
    }

    /** Counts get() calls so we can assert the lookup path is O(1) and bounded. */
    private static final class CountingMap<K, V> extends HashMap<K, V> {
        private int gets = 0;
        @Override
        public V get(Object key) {
            gets++;
            return super.get(key);
        }
        int gets() { return gets; }
    }

    /**
     * Subclass of {@link DirectedWeightedPseudograph} that counts vertexSet() invocations.
     * Used to prove no O(|V|) scan happens during from/to vertex resolution.
     */
    private static final class VertexSetCountingGraph extends DirectedWeightedPseudograph<DeviceVertex, AttackEdge> {
        private int vertexSetCalls = 0;
        VertexSetCountingGraph() { super(AttackEdge.class); }
        @Override
        public java.util.Set<DeviceVertex> vertexSet() {
            vertexSetCalls++;
            return super.vertexSet();
        }
        int vertexSetCalls() { return vertexSetCalls; }
    }
}
