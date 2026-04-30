package io.castellum.graph;

import io.castellum.risk.RiskScore;

/**
 * Pure static utility: edge weight and risk-contribution constants for the attack graph.
 *
 * <p>Weight is the Dijkstra cost (lower = easier exploit).
 * Risk contribution is the defender-pain dual (higher = worse).
 *
 * <p>For EXPLOITABLE_VULN edges, weight = 11.0 - composite_score, which:
 * <ul>
 *   <li>Ensures strictly-positive weights (composite ∈ [0,10] → weight ∈ [1,11]).</li>
 *   <li>Makes higher-severity CVEs produce lower-weight (= preferred) edges in Dijkstra.</li>
 * </ul>
 */
public final class EdgeWeights {

    private EdgeWeights() {
        throw new UnsupportedOperationException("static utility");
    }

    public static double sameSubnetWeight() { return 1.0; }

    public static double sameSubnetRisk() { return 0.0; }

    public static double weakCredPathWeight() { return 2.0; }

    public static double weakCredPathRisk() { return 5.0; }

    /**
     * Vuln edge weight = 11.0 - composite (strictly positive; inverts risk to effort).
     * composite ∈ [0, 10] → weight ∈ [1, 11].
     */
    public static double exploitableVulnWeight(RiskScore score) {
        return 11.0 - score.score().doubleValue();
    }

    /** Vuln edge risk contribution = composite score. */
    public static double exploitableVulnRisk(RiskScore score) {
        return score.score().doubleValue();
    }
}
