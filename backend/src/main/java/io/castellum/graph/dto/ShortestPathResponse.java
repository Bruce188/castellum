package io.castellum.graph.dto;

import java.math.BigDecimal;
import java.util.List;

public record ShortestPathResponse(
    long from,
    long to,
    List<HopDto> hops,
    int totalHops,
    BigDecimal cumulativeRisk,
    boolean pathFound
) {}
