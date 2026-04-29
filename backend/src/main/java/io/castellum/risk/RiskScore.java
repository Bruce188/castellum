package io.castellum.risk;

import java.math.BigDecimal;

public record RiskScore(BigDecimal score, BigDecimal cvssComponent, BigDecimal epssComponent,
                         BigDecimal kevComponent, BigDecimal criticalityComponent) {}
