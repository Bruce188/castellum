package io.castellum.graph.dto;

import io.castellum.graph.EdgeType;

import java.math.BigDecimal;

public record HopDto(
    long deviceId,
    String ipAddress,
    EdgeType edgeType,
    String attackTechniqueId,
    String attackTechniqueName,
    BigDecimal edgeRisk,
    BigDecimal cumulativeRisk,
    String cveId
) {}
