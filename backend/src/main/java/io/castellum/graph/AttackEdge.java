package io.castellum.graph;

import org.jgrapht.graph.DefaultWeightedEdge;

/**
 * JGraphT edge subclass with Castellum-specific metadata.
 *
 * <p>The JGraphT-managed weight is set by the caller via {@code graph.setEdgeWeight(edge, w)}
 * after {@code graph.addEdge(src, dst, edge)}. This class holds:
 *
 * <ul>
 *   <li>{@code type} — edge classification.</li>
 *   <li>{@code riskContribution} — defender-pain dual of the JGraphT weight (high = bad).
 *       For SAME_SUBNET: 0.0. For EXPLOITABLE_VULN: composite score in [0, 10]. For WEAK_CRED_PATH: 5.0 (constant).</li>
 *   <li>{@code cveId} — populated only for EXPLOITABLE_VULN; null otherwise.</li>
 * </ul>
 */
public class AttackEdge extends DefaultWeightedEdge {

    private final EdgeType type;
    private final double riskContribution;
    private final String cveId;

    public AttackEdge(EdgeType type, double riskContribution, String cveId) {
        if (type == null) throw new IllegalArgumentException("type must not be null");
        this.type = type;
        this.riskContribution = riskContribution;
        this.cveId = cveId;
    }

    public EdgeType getType() { return type; }

    public double getRiskContribution() { return riskContribution; }

    public String getCveId() { return cveId; }

    @Override
    public String toString() {
        return "AttackEdge[type=" + type + ", risk=" + riskContribution + ", cve=" + cveId + "]";
    }
}
