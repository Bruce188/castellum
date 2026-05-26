package io.castellum.web;

import io.castellum.graph.GraphService;
import io.castellum.graph.dto.ShortestPathResponse;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/graph")
public class GraphController {

    private final GraphService graphService;

    public GraphController(GraphService graphService) {
        this.graphService = graphService;
    }

    @GetMapping("/shortest-path")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public ShortestPathResponse shortestPath(@RequestParam("from") long from,
                                              @RequestParam("to") long to) {
        return graphService.shortestPath(from, to);
    }
}
