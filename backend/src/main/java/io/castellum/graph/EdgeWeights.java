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

    static final double SAME_SUBNET_WEIGHT = 1.0;
    static final double SAME_SUBNET_RISK = 0.0;
    static final double WEAK_CRED_PATH_WEIGHT = 2.0;
    static final double WEAK_CRED_PATH_RISK = 5.0;

    private EdgeWeights() {
        throw new UnsupportedOperationException("static utility");
    }

    public static double sameSubnetWeight() { return SAME_SUBNET_WEIGHT; }

    public static double sameSubnetRisk() { return SAME_SUBNET_RISK; }

    public static double weakCredPathWeight() { return WEAK_CRED_PATH_WEIGHT; }

    public static double weakCredPathRisk() { return WEAK_CRED_PATH_RISK; }

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
