import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
// @ts-expect-error - cose-bilkent has no shipped types
import coseBilkent from 'cytoscape-cose-bilkent';
import type { Device, DeviceRiskDto, DiscoveryScope, DiscoverySource } from '../api/types';
import { toRiskTier, tierColor } from '../lib/riskTier';
import { scopeBorderColor } from '../lib/scopeColors';
import { buildGatewayEdges } from '../lib/gatewayEdges';
import {
  scopeToZoneId,
  ZONE_DEFINITIONS,
  ZONE_COLORS,
  ZONE_BORDER_COLORS,
  ZONE_LABEL_COLORS,
  presentZoneIds,
} from '../lib/topologyZones';
import { type HighlightPath, makeEdgeKey, EDGE_STYLES } from './topologyConstants';

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
  /** Compound-aware: include label dimensions when sizing parent nodes. */
  nodeDimensionsIncludeLabels?: boolean;
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
  /**
   * True while the parent is still resolving per-device risk scores (the N+1
   * {@code deviceRisk} fanout). Drives a dashed-blue "computing" node style and
   * a corner badge so the operator can tell "scores still loading" apart from
   * "score is genuinely unknown" — both otherwise render as a grey node.
   */
  risksLoading?: boolean;
}

const SCOPE_CLASS: Record<DiscoveryScope, string | null> = {
  HOME: null,
  DOCKER_BRIDGE: 'scope-docker-bridge',
  LINK_LOCAL: 'scope-link-local',
  LOOPBACK: 'scope-loopback',
  PUBLIC: 'scope-public',
};

export function TopologyView({ devices, risksById, onNodeClick, onBackgroundClick, highlightPath, scopeVisibility, risksLoading }: Props) {
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
        { selector: 'edge', style: { 'line-color': EDGE_STYLES.subnet.color, 'curve-style': 'straight' as const, opacity: EDGE_STYLES.subnet.opacity, width: EDGE_STYLES.subnet.width } },
        // Gateway-hub edges (peer → gateway-of-/24) — solid, slightly heavier
        // than baseline so the hub structure reads through the layout.
        { selector: 'edge[kind = "gateway"]', style: { 'line-color': EDGE_STYLES.gateway.color, 'line-style': 'solid' as const, width: EDGE_STYLES.gateway.width, opacity: EDGE_STYLES.gateway.opacity } },
        // Docker-bridge synthetic edges (docker-host → DOCKER_BRIDGE device) —
        // dashed in the DOCKER_BRIDGE scope color so they read visually as a
        // distinct overlay rather than physical L2 adjacency.
        { selector: 'edge[kind = "docker-bridge"]', style: { 'line-color': EDGE_STYLES.dockerBridge.color, 'line-style': 'dashed' as const, width: EDGE_STYLES.dockerBridge.width, opacity: EDGE_STYLES.dockerBridge.opacity } },
        // Risk-still-loading overlay — dashed blue ring + dimmed fill. Appended
        // last so it wins border resolution while the parent's deviceRisk fanout
        // is in flight. The instant scores resolve the class is dropped and the
        // node snaps to its real tier color, making the grey→green transition a
        // deliberate "now computed" cue rather than an unexplained flicker.
        { selector: 'node.risk-loading', style: { 'border-width': 2, 'border-color': '#3b82f6', 'border-style': 'dashed' as const, opacity: 0.5 } },
        // ── Zone compound parent nodes ────────────────────────────────────────
        // Compound (parent) nodes are unsized — their bounds are derived from
        // their children. Style them with a semi-transparent fill + zone color
        // border so each zone region is labeled and visually distinct.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { selector: 'node[?zone]', style: {
          shape: 'roundrectangle' as const,
          label: 'data(label)',
          'font-size': 10,
          'text-valign': 'top' as const,
          'text-halign': 'center' as const,
          'background-opacity': 0.15,
          'border-width': 2,
          'border-style': 'dashed' as const,
          // Compound nodes derive their size from children; these values are
          // cytoscape string keywords not covered by the TS typings.
          width: 'label' as unknown as number,
          height: 'label' as unknown as number,
          padding: '20' as unknown as undefined,
        } },
        // Per-zone fill + border colors (inherit from ZONE_COLORS/ZONE_BORDER_COLORS).
        { selector: 'node.zone-zone-home',   style: { 'background-color': ZONE_COLORS['zone-home'],   'border-color': ZONE_BORDER_COLORS['zone-home'],   color: ZONE_LABEL_COLORS['zone-home'] } },
        { selector: 'node.zone-zone-docker', style: { 'background-color': ZONE_COLORS['zone-docker'], 'border-color': ZONE_BORDER_COLORS['zone-docker'], color: ZONE_LABEL_COLORS['zone-docker'] } },
        { selector: 'node.zone-zone-local',  style: { 'background-color': ZONE_COLORS['zone-local'],  'border-color': ZONE_BORDER_COLORS['zone-local'],  color: ZONE_LABEL_COLORS['zone-local'] } },
        { selector: 'node.zone-zone-public', style: { 'background-color': ZONE_COLORS['zone-public'], 'border-color': ZONE_BORDER_COLORS['zone-public'], color: ZONE_LABEL_COLORS['zone-public'] } },
        // ── Cross-zone edges — dashed + heavier to read across boundaries ─────
        { selector: 'edge[?crossZone]', style: {
          'line-style': 'dashed' as const,
          width: 2.5,
          opacity: 0.85,
        } },
        // Attack-path overlay — defined AFTER crossZone so the attack-path style
        // dominates for cross-zone path-highlighted edges (last selector wins).
        { selector: 'node.path-highlight', style: { 'border-width': 3, 'border-color': EDGE_STYLES.attackPath.color } },
        { selector: 'edge.path-highlight', style: { 'line-color': EDGE_STYLES.attackPath.color, 'line-style': 'dashed' as const, opacity: EDGE_STYLES.attackPath.opacity, width: EDGE_STYLES.attackPath.width } },
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
    // Expose the cytoscape instance for Playwright e2e assertions (position
    // data is only accessible through the cy API, not the DOM). Gated to
    // non-production so the debug handle is tree-shaken out of shipped bundles;
    // the e2e dev server (vite dev) still sets it.
    if (import.meta.env.MODE !== 'production') {
      (window as unknown as { __cytoscape?: cytoscape.Core }).__cytoscape = cy;
    }
    return () => {
      cy.destroy();
      cyRef.current = null;
      if (import.meta.env.MODE !== 'production') {
        delete (window as unknown as { __cytoscape?: cytoscape.Core }).__cytoscape;
      }
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

    // Source-class map — thin badge affordance mirroring SCOPE_CLASS pattern.
    // Active sources (ARP, MDNS, PCAP) get no extra class (they are the common case).
    // NMAP_SCAN and OT_PROBE carry a thin 'source-active-scan' marker so the topology
    // legend or future CSS can distinguish passive vs active discovery. DOCKER-discovered
    // containers carry 'source-docker' so they read distinctly from network-probed hosts.
    const SOURCE_CLASS: Partial<Record<DiscoverySource, string>> = {
      NMAP_SCAN: 'source-active-scan',
      OT_PROBE: 'source-active-scan',
      DOCKER: 'source-docker',
    };

    // ── Zone compound parent nodes ─────────────────────────────────────────
    // One parent node per zone that has at least one visible device. Each
    // parent node carries data.zone=true so tests (and selectors) can identify
    // it without parsing the id string.
    const presentScopes = new Set(visibleDevices.map(d => d.discoveryScope));
    const zoneIds = presentZoneIds(presentScopes);
    const zoneNodes = zoneIds.map(zid => ({
      data: {
        id: zid,
        label: ZONE_DEFINITIONS[zid].label,
        zone: true as const,
      },
      classes: `zone-${zid}`,
    }));

    const nodes = visibleDevices.map(d => {
      const risk = risksById.get(d.id);
      const score = risk ? Number(risk.score) : null;
      const tier = toRiskTier(score);
      const scopeClass = SCOPE_CLASS[d.discoveryScope];
      const sourceClass = d.discoverySource ? (SOURCE_CLASS[d.discoverySource] ?? null) : null;
      const extraClasses = [scopeClass, sourceClass].filter(Boolean).join(' ');
      // serviceCount suffix in the label surfaces the badge on the rendered graph.
      // The node style block above already renders data(label); no style change needed.
      // Guard: "host.docker.internal" and *.docker.internal are Docker bridge-gateway aliases
      // that must never render as a node label. The backend filters them before storage, but
      // this guard ensures any legacy data or race condition never surfaces the alias in the UI.
      const isBridgeAlias = (h: string | null) =>
        h != null && (h === 'host.docker.internal' || h.endsWith('.docker.internal'));
      const hostname = isBridgeAlias(d.hostname) ? null : d.hostname;
      const baseName = hostname ?? d.ipAddress;
      return {
        data: {
          id: String(d.id),
          // Assign each device to its zone compound parent node.
          parent: scopeToZoneId(d.discoveryScope),
          label: d.serviceCount > 0 ? `${baseName} · ${d.serviceCount} svc` : baseName,
          ip: d.ipAddress,
          riskTier: tier,
          // discoverySource threaded into node data for tooltip/legend consumers.
          // null when device predates V19 migration.
          discoverySource: d.discoverySource,
          serviceCount: d.serviceCount,
        },
        classes: [`risk-${tier}`, extraClasses, risksLoading ? 'risk-loading' : '']
          .filter(Boolean)
          .join(' '),
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
    // Zone parent nodes must be added BEFORE device nodes so cytoscape can
    // resolve the parent references when child nodes are added.
    cy.add([...zoneNodes, ...nodes, ...edges, ...extraEdges]);
    // randomize:true prevents collinear collapse on sparse graphs — without it
    // cose-bilkent starts from degenerate (0,0) seed positions and converges
    // to a straight line when the fleet is small.
    // nodeDimensionsIncludeLabels:true ensures compound parent nodes size to
    // include their zone label, keeping children inside the labeled boundary.
    const layoutOptions: CoseBilkentLayoutOptions = {
      name: 'cose-bilkent',
      idealEdgeLength: 100,
      nodeRepulsion: 4500,
      animate: false,
      randomize: true,
      nodeDimensionsIncludeLabels: true,
    };
    cy.layout(layoutOptions).run();
  }, [devices, risksById, highlightPath, scopeVisibility, risksLoading]);

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
    <div className="relative w-full h-full">
      <div
        ref={containerRef}
        data-testid="topology-canvas"
        className="w-full h-full"
        title="Node color reflects composite risk tier (CVE severity × KEV × EPSS × criticality). Update operator-set criticality on the device detail panel."
      />
      {risksLoading && (
        // Pinned top-LEFT, not top-right: the TopologyLegend owns the top-right
        // corner at z-10 and would otherwise cover this badge. Left corner is
        // clear (the detail panel is right-pinned; the empty/error states are
        // centered) so the "computing" cue stays visible during the fanout.
        <div
          data-testid="topology-risk-loading"
          className="absolute top-2 left-2 flex items-center gap-2 rounded border border-blue-200 bg-blue-50/90 px-2.5 py-1 text-xs text-blue-700 shadow-sm pointer-events-none"
        >
          <span className="inline-block h-2 w-2 rounded-full bg-blue-500 animate-pulse" />
          Computing risk scores…
        </div>
      )}
    </div>
  );
}
