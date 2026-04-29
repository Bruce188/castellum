package io.castellum.risk;

public record EpssRow(String cveId, double epss, double percentile) {
    public EpssRow {
        if (cveId == null || cveId.isBlank()) throw new IllegalArgumentException("cveId must be non-blank");
        if (epss < 0.0 || epss > 1.0) throw new IllegalArgumentException("epss must be in [0,1]: " + epss);
        if (percentile < 0.0 || percentile > 1.0) throw new IllegalArgumentException("percentile must be in [0,1]: " + percentile);
    }
}
