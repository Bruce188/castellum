/**
 * Shared topology constants and helpers extracted from TopologyView.tsx so that
 * non-component exports do not violate the react-refresh/only-export-components
 * rule (which requires every export from a JSX module to be a React component).
 */

/**
 * Optional path highlight overlay. {@link #nodeIds} is the ordered list of
 * device ids on the path (including endpoints); {@link #edgeKeys} contains
 * undirected edge identifiers in {@code min(a,b)-max(a,b)} form so we don't
 * have to care which direction Cytoscape stored the edge in.
 *
 * <p>When supplied, the view ADDS the corresponding nodes and one synthetic
 * edge per pair to the graph (so the path is visible even between devices
 * that share no /24) and applies the {@code path-highlight} class to them.
 */
export interface HighlightPath {
  nodeIds: number[];
  edgeKeys?: string[];
}

/** Canonical undirected edge key — used by both view and caller so they match. */
export function makeEdgeKey(a: number, b: number): string {
  return a <= b ? `${a}-${b}` : `${b}-${a}`;
}
