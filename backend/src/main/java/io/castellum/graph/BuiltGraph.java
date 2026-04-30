package io.castellum.graph;

import org.jgrapht.Graph;

import java.util.Map;

/**
 * Result of {@link GraphBuilder#build()}: the assembled JGraphT graph plus the
 * vertex-by-device-id map constructed during the build. Callers that need to
 * resolve a {@link DeviceVertex} by device id should use {@link #vertexById()}
 * for O(1) lookup instead of scanning {@link Graph#vertexSet()}.
 */
public record BuiltGraph(Graph<DeviceVertex, AttackEdge> graph,
                          Map<Long, DeviceVertex> vertexById) {
}
