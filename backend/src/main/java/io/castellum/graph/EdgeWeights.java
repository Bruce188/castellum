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

    /**
     * Gateway-pivot edge Dijkstra cost. Strictly positive; heavier than SAME_SUBNET (1.0) and
     * WEAK_CRED_PATH (2.0) so within-subnet moves are preferred and a cross-scope pivot is only
     * taken when no cheaper path exists. Sits within the 1–11 EXPLOITABLE_VULN band.
     */
    public static double gatewayPivotWeight() { return 3.0; }

    /** Gateway-pivot edge risk contribution (defender-pain dual of weight). */
    public static double gatewayPivotRisk() { return 4.0; }
}
