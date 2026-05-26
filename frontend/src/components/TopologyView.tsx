import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
// @ts-expect-error - cose-bilkent has no shipped types
import coseBilkent from 'cytoscape-cose-bilkent';
import type { Device, DeviceRiskDto, DiscoveryScope } from '../api/types';
import { toRiskTier, tierColor } from '../lib/riskTier';
import { scopeBorderColor } from '../lib/scopeColors';
import { buildGatewayEdges } from '../lib/gatewayEdges';
import { type HighlightPath, makeEdgeKey } from './topologyConstants';

cytoscape.use(coseBilkent);

// Local typing for cose-bilkent layout options. The package ships no types
// (see @ts-expect-error on the import above) and cytoscape.LayoutOptions is a
// union of built-in layout shapes that does not include 'cose-bilkent'.
// Extend BaseLayoutOptions (which is one arm of the LayoutOptions union and
// only requires `name: string`) so cy.layout() accepts the value without a
// cast — this lets us drop the `as any` previously needed at the call site.
interface CoseBilkentLayoutOptions extends cytoscape.BaseLayoutOptions {
  name: 'cose-bilkent';
  idealEdgeLength?: number;
  nodeRepulsion?: number;
  animate?: boolean;
  randomize?: boolean;
}

interface Props {
  devices: Device[];
  risksById: Map<number, DeviceRiskDto>;
  onNodeClick: (deviceId: number) => void;
  onBackgroundClick: () => void;
  /** When set, marks the listed nodes/edges with {@code path-highlight}. */
  highlightPath?: HighlightPath | null;
  /**
   * Per-scope visibility map. Unset keys default to {@code true}; nodes with a
   * scope keyed {@code false} are filtered BEFORE edge-building so dangling
   * subnet edges are structurally impossible.
   */
  scopeVisibility?: Record<DiscoveryScope, boolean>;
}

const SCOPE_CLASS: Record<DiscoveryScope, string | null> = {
  HOME: null,
  DOCKER_BRIDGE: 'scope-docker-bridge',
  LINK_LOCAL: 'scope-link-local',
  LOOPBACK: 'scope-loopback',
  PUBLIC: 'scope-public',
};

export function TopologyView({ devices, risksById, onNodeClick, onBackgroundClick, highlightPath, scopeVisibility }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  /**
   * Callback refs (kept fresh by the two effects below) decouple the Cytoscape
   * init effect from the parent's handler identity. Without this indirection,
   * any change to onNodeClick or onBackgroundClick would change the init
   * effect's dependency closure, forcing cy.destroy() + new cytoscape() on
   * every parent re-render — losing layout state and breaking the React 19
   * strict-mode `topologyView_doesNotCallDestroyOnRiskUpdate` invariant.
   *
   * The two micro-effects below patch the refs each render so the cytoscape
   * tap handlers (which read .current) always invoke the latest props.
   */
  const onNodeClickRef = useRef(onNodeClick);
  const onBgClickRef = useRef(onBackgroundClick);

  // Keep latest callbacks without re-initializing cytoscape on every render.
  useEffect(() => { onNodeClickRef.current = onNodeClick; }, [onNodeClick]);
  useEffect(() => { onBgClickRef.current = onBackgroundClick; }, [onBackgroundClick]);

  // Init effect — runs ONCE on mount; instance lives in cyRef and is reused for every prop update.
  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      elements: [],
      style: [
        { selector: 'node', style: { label: 'data(label)', 'font-size': 12, 'text-valign': 'bottom' as const, 'text-halign': 'center' as const, width: 30, height: 30, 'border-width': 1, 'border-color': '#1f2937' } },
        { selector: 'node.risk-low',     style: { 'background-color': tierColor.low } },
        { selector: 'node.risk-med',     style: { 'background-color': tierColor.med } },
        { selector: 'node.risk-high',    style: { 'background-color': tierColor.high } },
        { selector: 'node.risk-crit',    style: { 'background-color': tierColor.crit } },
        { selector: 'node.risk-unknown', style: { 'background-color': tierColor.unknown } },
        // Per-scope border overrides — appended AFTER node.risk-* so Cytoscape's
        // last-matching-selector resolution wins for non-HOME nodes. HOME nodes
        // get no scope-* class and keep the default '#1f2937' border above.
        { selector: 'node.scope-docker-bridge', style: { 'border-width': 2, 'border-color': scopeBorderColor.DOCKER_BRIDGE } },
        { selector: 'node.scope-link-local',   style: { 'border-width': 2, 'border-color': scopeBorderColor.LINK_LOCAL } },
        { selector: 'node.scope-loopback',     style: { 'border-width': 2, 'border-color': scopeBorderColor.LOOPBACK } },
        { selector: 'node.scope-public',       style: { 'border-width': 2, 'border-color': scopeBorderColor.PUBLIC } },
        { selector: 'edge', style: { 'line-color': '#9ca3af', 'curve-style': 'straight' as const, opacity: 0.5, width: 1 } },
        // Gateway-hub edges (peer → gateway-of-/24) — solid, slightly heavier
        // than baseline so the hub structure reads through the layout.
        { selector: 'edge[kind = "gateway"]', style: { 'line-color': '#9ca3af', 'line-style': 'solid' as const, width: 2, opacity: 0.7 } },
        // Docker-bridge synthetic edges (docker-host → DOCKER_BRIDGE device) —
        // dashed in the DOCKER_BRIDGE scope color so they read visually as a
        // distinct overlay rather than physical L2 adjacency.
        { selector: 'edge[kind = "docker-bridge"]', style: { 'line-color': scopeBorderColor.DOCKER_BRIDGE, 'line-style': 'dashed' as const, width: 2, opacity: 0.8 } },
        // Attack-path overlay — bright red ring on nodes, dashed red stroke on edges.
        { selector: 'node.path-highlight', style: { 'border-width': 3, 'border-color': '#dc2626' } },
        { selector: 'edge.path-highlight', style: { 'line-color': '#dc2626', 'line-style': 'dashed' as const, opacity: 1, width: 3 } },
      ],
    });

    cy.on('tap', 'node', evt => {
      const id = Number(evt.target.id());
      if (Number.isInteger(id)) onNodeClickRef.current(id);
    });
    cy.on('tap', evt => {
      if (evt.target === cy) onBgClickRef.current();
    });

    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, []);

  // Sync effect — patches the existing cytoscape instance in place rather than tearing it down.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    // Filter by scope visibility BEFORE building edges so dangling subnet edges
    // are structurally impossible. Unset keys default to true (legend not mounted).
    const visibleDevices = scopeVisibility
      ? devices.filter(d => scopeVisibility[d.discoveryScope] ?? true)
      : devices;

    const nodes = visibleDevices.map(d => {
      const risk = risksById.get(d.id);
      const score = risk ? Number(risk.score) : null;
      const tier = toRiskTier(score);
      const scopeClass = SCOPE_CLASS[d.discoveryScope];
      return {
        data: {
          id: String(d.id),
          label: d.hostname ?? d.ipAddress,
          ip: d.ipAddress,
          riskTier: tier,
        },
        classes: scopeClass ? `risk-${tier} ${scopeClass}` : `risk-${tier}`,
      };
    });

    const edges = buildGatewayEdges(visibleDevices);

    // When a path is provided, add ad-hoc edges for path pairs that aren't
    // already covered by the subnet-edge layer (the attack graph may traverse
    // EXPLOITABLE_VULN edges between devices on different /24s).
    const extraEdges: Array<{ data: { id: string; source: string; target: string; kind: 'path' } }> = [];
    if (highlightPath && highlightPath.nodeIds.length >= 2) {
      const seen = new Set<string>(edges.map(e => e.data.id));
      for (let i = 0; i < highlightPath.nodeIds.length - 1; i++) {
        const a = highlightPath.nodeIds[i];
        const b = highlightPath.nodeIds[i + 1];
        const key = makeEdgeKey(a, b);
        const fwd = `e-${Math.min(a, b)}-${Math.max(a, b)}`;
        const id = `pe-${key}`;
        if (seen.has(fwd) || seen.has(id)) continue;
        seen.add(id);
        extraEdges.push({ data: { id, source: String(a), target: String(b), kind: 'path' } });
      }
    }

    cy.elements().remove();
    cy.add([...nodes, ...edges, ...extraEdges]);
    const layoutOptions: CoseBilkentLayoutOptions = {
      name: 'cose-bilkent',
      idealEdgeLength: 100,
      nodeRepulsion: 4500,
      animate: false,
      randomize: false,
    };
    cy.layout(layoutOptions).run();
  }, [devices, risksById, highlightPath, scopeVisibility]);

  // Apply path-highlight classes — kept in its own effect so re-highlighting
  // does not re-run the layout. Reads the latest highlightPath each render.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements('.path-highlight').removeClass('path-highlight');
    if (!highlightPath || highlightPath.nodeIds.length === 0) return;
    const nodeIdSet = new Set(highlightPath.nodeIds.map(String));
    cy.nodes().forEach(n => {
      if (nodeIdSet.has(n.id())) n.addClass('path-highlight');
    });
    // Build the set of expected canonical edge keys from the path pairs (and
    // also accept caller-supplied edgeKeys if present).
    const expected = new Set<string>(highlightPath.edgeKeys ?? []);
    for (let i = 0; i < highlightPath.nodeIds.length - 1; i++) {
      expected.add(makeEdgeKey(highlightPath.nodeIds[i], highlightPath.nodeIds[i + 1]));
    }
    cy.edges().forEach(e => {
      const a = Number(e.data('source'));
      const b = Number(e.data('target'));
      if (Number.isFinite(a) && Number.isFinite(b) && expected.has(makeEdgeKey(a, b))) {
        e.addClass('path-highlight');
      }
    });
  }, [highlightPath, devices]);

  return (
    <div
      ref={containerRef}
      data-testid="topology-canvas"
      className="w-full h-full"
      title="Node color reflects composite risk tier (CVE severity × KEV × EPSS × criticality). Update operator-set criticality on the device detail panel."
    />
  );
}
