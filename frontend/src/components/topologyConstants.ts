/**
 * Shared topology constants and helpers extracted from TopologyView.tsx so that
 * non-component exports do not violate the react-refresh/only-export-components
 * rule (which requires every export from a JSX module to be a React component).
 */
import { scopeBorderColor } from '../lib/scopeColors';

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

export interface EdgeStyleToken {
  color: string;
  style: 'straight' | 'solid' | 'dashed';
  width: number;
  opacity: number;
}

/**
 * Drawn edge strokes — single source of truth for BOTH TopologyView's cytoscape
 * stylesheet and the attack-graph edge legend so the two cannot drift. Values mirror
 * the cytoscape style block (TopologyView.tsx). 'subnet' uses curve-style straight;
 * the rest use line-style.
 */
export const EDGE_STYLES = {
  subnet:       { color: '#9ca3af', style: 'straight', width: 1, opacity: 0.5 },
  gateway:      { color: '#9ca3af', style: 'solid',    width: 2, opacity: 0.7 },
  dockerBridge: { color: scopeBorderColor.DOCKER_BRIDGE, style: 'dashed', width: 2, opacity: 0.8 },
  attackPath:   { color: '#dc2626', style: 'dashed',   width: 3, opacity: 1 },
} as const satisfies Record<string, EdgeStyleToken>;
