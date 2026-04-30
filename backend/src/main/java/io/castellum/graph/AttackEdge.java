package io.castellum.graph;

import org.jgrapht.graph.DefaultWeightedEdge;

import java.util.Locale;

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
 *   <li>{@code techniqueId} — ATT&amp;CK technique id captured at edge build time. Populated for
 *       EXPLOITABLE_VULN (e.g. T1190 / T1210 service-aware); null for SAME_SUBNET.</li>
 * </ul>
 */
public class AttackEdge extends DefaultWeightedEdge {

    private final EdgeType type;
    private final double riskContribution;
    private final String cveId;
    private final String techniqueId;

    public AttackEdge(EdgeType type, double riskContribution, String cveId) {
        this(type, riskContribution, cveId, null);
    }

    public AttackEdge(EdgeType type, double riskContribution, String cveId, String techniqueId) {
        if (type == null) throw new IllegalArgumentException("type must not be null");
        this.type = type;
        this.riskContribution = riskContribution;
        this.cveId = cveId;
        this.techniqueId = techniqueId;
    }

    public EdgeType getType() { return type; }

    public double getRiskContribution() { return riskContribution; }

    public String getCveId() { return cveId; }

    public String getTechniqueId() { return techniqueId; }

    @Override
    public String toString() {
        return String.format(Locale.ROOT,
            "AttackEdge[type=%s, risk=%.3f, cve=%s, technique=%s]",
            type, riskContribution, cveId, techniqueId);
    }
}
