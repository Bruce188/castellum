package io.castellum.risk;

public record RiskInputs(double cvssNormalized, double epss, boolean kev, Criticality criticality) {
    public RiskInputs {
        if (cvssNormalized < 0.0 || cvssNormalized > 1.0) {
            throw new IllegalArgumentException("cvssNormalized must be in [0,1]: " + cvssNormalized);
        }
        if (epss < 0.0 || epss > 1.0) {
            throw new IllegalArgumentException("epss must be in [0,1]: " + epss);
        }
        if (criticality == null) {
            throw new IllegalArgumentException("criticality must not be null");
        }
    }
}
