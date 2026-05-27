package io.castellum.graph;

/**
 * Discriminator for the edge classes in Castellum's attack graph.
 *
 * <ul>
 *   <li>{@link #SAME_SUBNET} — bidirectional adjacency derived from /24 grouping; constant weight 1.0.</li>
 *   <li>{@link #EXPLOITABLE_VULN} — directed toward the device hosting the vuln; weight = 11.0 - composite_score.</li>
 *   <li>{@link #WEAK_CRED_PATH} — typed-but-empty seam in v1 (no signal source); constant weight 2.0.</li>
 *   <li>{@link #GATEWAY_PIVOT} — bridges two discovery scopes through a single pivot/gateway node; weight ~3.0.</li>
 * </ul>
 */
public enum EdgeType {
    SAME_SUBNET,
    EXPLOITABLE_VULN,
    WEAK_CRED_PATH,
    GATEWAY_PIVOT
}
