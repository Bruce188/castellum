package io.castellum.graph;

import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.DijkstraShortestPath;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Thin wrapper over JGraphT's {@link DijkstraShortestPath}. Returns an {@link Optional}
 * that is empty when no path exists — JGraphT's native getPath returns null in that case.
 */
@Component
public class ShortestPathFinder {

    public Optional<GraphPath<DeviceVertex, AttackEdge>> findPath(
            Graph<DeviceVertex, AttackEdge> graph,
            DeviceVertex source,
            DeviceVertex target) {
        return Optional.ofNullable(new DijkstraShortestPath<>(graph).getPath(source, target));
    }
}
