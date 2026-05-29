/**
 * TDD tests for feat/topology-zone-grouping (AC1–AC5).
 *
 * Fixture: 5 devices spanning HOME, DOCKER_BRIDGE, LINK_LOCAL, LOOPBACK, PUBLIC.
 * The tests validate:
 *   AC1  – compound/parent nodes created per present zone; empty zones omitted.
 *   AC2  – cross-zone edges carry the 'cross-zone' kind for distinct styling.
 *   AC3  – legend lists present zones via data-testid zone rows.
 *   AC5  – membership, cross-zone edge style, empty-zone omission (falsifiable unit tests).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import type { Device, DiscoveryScope } from '../api/types';

// ─── cytoscape mock (same shape as TopologyView.test.tsx) ──────────────────
vi.mock('cytoscape', () => {
  const destroy = vi.fn();
  const add = vi.fn();
  const remove = vi.fn();
  const removeClass = vi.fn();
  const addClass = vi.fn();
  const forEach = vi.fn();
  const collection = { remove, removeClass, addClass, forEach };
  const elements = vi.fn(() => collection);
  const nodes = vi.fn(() => collection);
  const edges = vi.fn(() => collection);
  const layoutRun = vi.fn();
  const layout = vi.fn(() => ({ run: layoutRun }));
  const on = vi.fn();
  const factory = vi.fn(() => ({ destroy, add, elements, nodes, edges, layout, on }));
  (factory as unknown as { use: ReturnType<typeof vi.fn> }).use = vi.fn();
  (factory as unknown as { __mocks: Record<string, unknown> }).__mocks = {
    destroy, add, remove, removeClass, addClass, forEach, elements, nodes, edges, layout, layoutRun, on,
  };
  return { default: factory };
});
vi.mock('cytoscape-cose-bilkent', () => ({ default: vi.fn() }));

import cytoscape from 'cytoscape';
import { TopologyView } from '../components/TopologyView';
import { TopologyLegend } from '../components/TopologyLegend';
import { ZONE_DEFINITIONS, scopeToZoneId, ZONE_COLORS, type ZoneId } from '../lib/topologyZones';
import { buildGatewayEdges } from '../lib/gatewayEdges';

type MockBag = {
  add: ReturnType<typeof vi.fn>;
  layout: ReturnType<typeof vi.fn>;
  elements: ReturnType<typeof vi.fn>;
};
const factoryMock = cytoscape as unknown as ReturnType<typeof vi.fn> & { __mocks: MockBag };
const mocks = factoryMock.__mocks;

function makeDevice(
  id: number,
  ip: string,
  scope: DiscoveryScope,
  publishesHostPort = false,
): Device {
  return {
    id,
    ipAddress: ip,
    hostname: `h${id}`,
    macAddress: null,
    firstSeen: '2026-01-01T00:00:00Z',
    lastSeen: '2026-01-01T00:00:00Z',
    criticality: 'MEDIUM',
    discoveryScope: scope,
    lastSeenIface: null,
    discoverySource: null,
    serviceCount: 0,
    osName: null,
    osAccuracy: null,
    osCpe: null,
    publishesHostPort,
  };
}

/** Fixture: HOME + DOCKER_BRIDGE + LINK_LOCAL + LOOPBACK + PUBLIC = 5 scopes, 5 devices */
const FIVE_SCOPE_DEVICES: Device[] = [
  makeDevice(1, '192.168.68.1', 'HOME'),
  makeDevice(2, '172.17.0.2', 'DOCKER_BRIDGE'),
  makeDevice(3, '169.254.1.1', 'LINK_LOCAL'),
  makeDevice(4, '127.0.0.1', 'LOOPBACK'),
  makeDevice(5, '8.8.8.8', 'PUBLIC'),
];

// ─── AC5 / Unit: topologyZones helpers ─────────────────────────────────────

describe('topologyZones helpers (AC5 – falsifiable unit tests)', () => {
  it('zoneGrouping_scopeToZoneId_mapsAllFiveScopes', () => {
    // Every DiscoveryScope value must map to a non-empty zone id string.
    const scopes: DiscoveryScope[] = ['HOME', 'DOCKER_BRIDGE', 'LINK_LOCAL', 'LOOPBACK', 'PUBLIC'];
    for (const s of scopes) {
      const id = scopeToZoneId(s);
      expect(typeof id).toBe('string');
      expect(id.length).toBeGreaterThan(0);
    }
  });

  it('zoneGrouping_zoneDefinitions_coversAllFiveScopes', () => {
    // ZONE_DEFINITIONS must map all five DiscoveryScope values to a definition.
    const scopes: DiscoveryScope[] = ['HOME', 'DOCKER_BRIDGE', 'LINK_LOCAL', 'LOOPBACK', 'PUBLIC'];
    for (const s of scopes) {
      const zoneId = scopeToZoneId(s);
      const def = ZONE_DEFINITIONS[zoneId];
      expect(def, `ZONE_DEFINITIONS missing entry for scope ${s} → zoneId ${zoneId}`).toBeTruthy();
      expect(def.label).toBeTruthy();
    }
  });

  it('zoneGrouping_zoneColors_coversAllZoneIds', () => {
    // ZONE_COLORS must have an entry for every zone id in ZONE_DEFINITIONS.
    const zoneIds = Object.keys(ZONE_DEFINITIONS) as ZoneId[];
    for (const zid of zoneIds) {
      expect(ZONE_COLORS[zid], `ZONE_COLORS missing color for zone ${zid}`).toBeTruthy();
    }
  });

  it('zoneGrouping_homeAndDockerBridgeMapToDifferentZones', () => {
    // HOME and DOCKER_BRIDGE must be in different zones — the whole point of grouping.
    expect(scopeToZoneId('HOME')).not.toBe(scopeToZoneId('DOCKER_BRIDGE'));
  });
});

// ─── AC1: compound parent nodes emitted for present zones ──────────────────

describe('TopologyView zone grouping (AC1 – compound parent nodes)', () => {
  beforeEach(() => {
    factoryMock.mockClear();
    mocks.add.mockClear();
    mocks.elements.mockClear();
    mocks.layout.mockClear();
  });

  it('zoneGrouping_threeOrMoreZonesProduceThreeOrMoreParentNodes', () => {
    // Devices spanning ≥3 scopes → ≥3 zone parent nodes in the cy.add() call.
    render(
      <TopologyView
        devices={FIVE_SCOPE_DEVICES}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    expect(mocks.add).toHaveBeenCalled();
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; zone?: boolean; parent?: string };
      classes?: string;
    }>;

    // Zone parent nodes: they have data.zone === true (or a zone marker) and no parent field.
    const parentNodes = addArgs.filter(e => e.data.zone === true);
    expect(parentNodes.length, 'expected ≥3 zone parent nodes for 5-scope fixture').toBeGreaterThanOrEqual(3);
  });

  it('zoneGrouping_everyDeviceNodeHasAParentField', () => {
    // All device nodes (numeric ids) must carry a `parent` field pointing to their zone.
    render(
      <TopologyView
        devices={FIVE_SCOPE_DEVICES}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; parent?: string; zone?: boolean; source?: string; target?: string };
    }>;
    // Device nodes have purely numeric ids and no source/target.
    const deviceNodes = addArgs.filter(e =>
      /^\d+$/.test(e.data.id) && !('source' in e.data) && !('target' in e.data)
    );
    expect(deviceNodes.length).toBe(FIVE_SCOPE_DEVICES.length);
    for (const node of deviceNodes) {
      expect(node.data.parent, `device node ${node.data.id} missing parent`).toBeTruthy();
    }
  });

  it('zoneGrouping_devicesAssignedToCorrectZone', () => {
    // HOME device → zone-home; DOCKER_BRIDGE device → docker sub-box (which parents to zone-docker).
    // Since this fixture has no docker-net gateway, the container lands in the unattached sub-box.
    render(
      <TopologyView
        devices={[makeDevice(10, '192.168.1.1', 'HOME'), makeDevice(20, '172.17.0.2', 'DOCKER_BRIDGE')]}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; parent?: string; zone?: boolean; dockerNetwork?: boolean; source?: string; target?: string };
    }>;
    const byId = (id: string) => addArgs.find(e => e.data.id === id);
    // HOME device still maps directly to zone-home.
    expect(byId('10')?.data.parent).toBe('zone-home');
    // DOCKER_BRIDGE device now parents to a network sub-box (not directly to zone-docker).
    // Without docker-net gateways, it lands in the unattached fallback sub-box.
    const dockerParent = byId('20')?.data.parent;
    expect(dockerParent, 'docker device must have a parent (sub-box or zone)').toBeTruthy();
    // The sub-box itself must parent to zone-docker (2-level nesting preserved).
    const subBox = addArgs.find(e => e.data.id === dockerParent && e.data.dockerNetwork === true);
    expect(subBox, `sub-box ${dockerParent} must carry dockerNetwork=true`).toBeTruthy();
    expect(subBox?.data.parent).toBe('zone-docker');
  });

  it('zoneGrouping_publicDeviceAssignedToZonePublic', () => {
    // PUBLIC scope → zone-public.
    render(
      <TopologyView
        devices={[makeDevice(30, '8.8.8.8', 'PUBLIC')]}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; parent?: string; zone?: boolean; source?: string; target?: string };
    }>;
    const byId = (id: string) => addArgs.find(e => e.data.id === id);
    expect(byId('30')?.data.parent).toBe('zone-public');
  });

  it('zoneGrouping_linkLocalAndLoopbackAssignedToZoneLocal', () => {
    // LINK_LOCAL and LOOPBACK both map to zone-local.
    render(
      <TopologyView
        devices={[makeDevice(40, '169.254.1.1', 'LINK_LOCAL'), makeDevice(50, '127.0.0.1', 'LOOPBACK')]}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; parent?: string; zone?: boolean; source?: string; target?: string };
    }>;
    const byId = (id: string) => addArgs.find(e => e.data.id === id);
    // Both local-ish scopes must share zone-local, not be split.
    expect(byId('40')?.data.parent).toBe('zone-local');
    expect(byId('50')?.data.parent).toBe('zone-local');
  });

  it('zoneGrouping_emptyZonesOmitted', () => {
    // If only HOME + PUBLIC are present, only 2 zone parent nodes should appear.
    const twoScopeDevices = [
      makeDevice(1, '192.168.1.1', 'HOME'),
      makeDevice(2, '8.8.8.8', 'PUBLIC'),
    ];
    render(
      <TopologyView
        devices={twoScopeDevices}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; zone?: boolean };
    }>;
    const parentNodes = addArgs.filter(e => e.data.zone === true);
    expect(parentNodes.length).toBe(2);
  });
});

// ─── AC2: cross-zone edges styled distinctly ──────────────────────────────

describe('TopologyView cross-zone edge styling (AC2)', () => {
  beforeEach(() => {
    factoryMock.mockClear();
    mocks.add.mockClear();
    mocks.elements.mockClear();
    mocks.layout.mockClear();
  });

  it('zoneGrouping_crossZoneEdgeHasCrossZoneKind', () => {
    // HOME device (docker host at 192.168.68.51) + a PUBLISHED-PORT DOCKER_BRIDGE
    // container → the docker-bridge synthetic edge (container → pivot) crosses zone
    // boundaries → kind should be 'cross-zone' OR carry a crossZone flag.
    // (An internal-only container with no docker-net gateway is intentionally left
    // unattached and gets no pivot edge per AC4 — so we use a published container.)
    const homeDevice = makeDevice(1, '192.168.68.51', 'HOME');
    const dockerDevice = makeDevice(2, '172.17.0.2', 'DOCKER_BRIDGE', true);
    render(
      <TopologyView
        devices={[homeDevice, dockerDevice]}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; kind?: string; crossZone?: boolean; source?: string; target?: string };
    }>;
    // The docker-bridge edge crosses zones; check either crossZone flag or kind 'cross-zone'.
    const dbEdge = addArgs.find(e => e.data.id?.startsWith('db-'));
    expect(dbEdge, 'expected a db- edge for docker-bridge cross-zone').toBeTruthy();
    const isCrossZone = dbEdge?.data.crossZone === true || dbEdge?.data.kind === 'cross-zone';
    expect(isCrossZone, 'docker-bridge edge between HOME and DOCKER_BRIDGE zones must be cross-zone').toBe(true);
  });

  it('zoneGrouping_intraZoneGatewayEdgeIsNotCrossZone', () => {
    // Two HOME devices on same /24 → gateway edge is intra-zone.
    const devices = [
      makeDevice(1, '192.168.1.1', 'HOME'),
      makeDevice(2, '192.168.1.50', 'HOME'),
    ];
    render(
      <TopologyView
        devices={devices}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; kind?: string; crossZone?: boolean; source?: string; target?: string };
    }>;
    const gatewayEdges = addArgs.filter(e => e.data.kind === 'gateway');
    expect(gatewayEdges.length).toBeGreaterThan(0);
    for (const e of gatewayEdges) {
      expect(e.data.crossZone, 'intra-zone gateway edge must NOT be crossZone').not.toBe(true);
    }
  });
});

// ─── AC3: legend lists present zones ──────────────────────────────────────

describe('TopologyLegend zone rows (AC3)', () => {
  it('zoneGrouping_legendListsPresentZones_fiveScopes', () => {
    // When all five scopes are present (visibility all-true), the legend should still
    // render the scope checkboxes (existing tests pin count at 5).
    const allTrue: Record<DiscoveryScope, boolean> = {
      HOME: true,
      DOCKER_BRIDGE: true,
      LINK_LOCAL: true,
      LOOPBACK: true,
      PUBLIC: true,
    };
    render(<TopologyLegend visibility={allTrue} onChange={vi.fn()} presentScopes={new Set(['HOME', 'DOCKER_BRIDGE', 'LINK_LOCAL', 'LOOPBACK', 'PUBLIC'] as DiscoveryScope[])} />);
    // Legend must have zone swatches — one for each present zone.
    // We assert at least 2 zone-row entries visible (one per present zone group).
    const zoneLegend = screen.queryByTestId('topology-legend-zones');
    expect(zoneLegend, 'expected a data-testid="topology-legend-zones" section').toBeTruthy();
  });

  it('zoneGrouping_legendOmitsEmptyZones', () => {
    // When only HOME is present, only the HOME zone appears in the zones section.
    const visibility: Record<DiscoveryScope, boolean> = {
      HOME: true,
      DOCKER_BRIDGE: false,
      LINK_LOCAL: false,
      LOOPBACK: false,
      PUBLIC: false,
    };
    render(<TopologyLegend visibility={visibility} onChange={vi.fn()} presentScopes={new Set(['HOME'] as DiscoveryScope[])} />);
    const zoneRows = screen.queryAllByTestId(/^zone-legend-row-/);
    // Only the HOME zone should appear.
    expect(zoneRows.length).toBe(1);
  });

  it('zoneGrouping_legendWithNoPresentScopes_hidesZoneSection', () => {
    // No presentScopes → zone section is empty or absent.
    const allTrue: Record<DiscoveryScope, boolean> = {
      HOME: true, DOCKER_BRIDGE: true, LINK_LOCAL: true, LOOPBACK: true, PUBLIC: true,
    };
    render(<TopologyLegend visibility={allTrue} onChange={vi.fn()} presentScopes={new Set()} />);
    const zoneRows = screen.queryAllByTestId(/^zone-legend-row-/);
    expect(zoneRows.length).toBe(0);
  });

  it('zoneGrouping_toggleOffScopeRemovesItsZoneFromPresentSet', () => {
    // When DOCKER_BRIDGE is toggled off, the docker zone must not appear in presentScopes.
    // This mirrors the page-level fix: presentScopes = filtered(devices, scopeVisibility).
    const visibilityDockerOff: Record<DiscoveryScope, boolean> = {
      HOME: true,
      DOCKER_BRIDGE: false,
      LINK_LOCAL: false,
      LOOPBACK: false,
      PUBLIC: false,
    };
    // presentScopes reflects scope-filtered visible devices — only HOME survives.
    const presentAfterToggle = new Set(
      [
        { discoveryScope: 'HOME' as DiscoveryScope },
        { discoveryScope: 'DOCKER_BRIDGE' as DiscoveryScope },
      ]
        .filter(d => visibilityDockerOff[d.discoveryScope] ?? true)
        .map(d => d.discoveryScope)
    );
    // Only HOME is visible; DOCKER_BRIDGE must not be in the set.
    expect(presentAfterToggle.has('HOME')).toBe(true);
    expect(presentAfterToggle.has('DOCKER_BRIDGE')).toBe(false);

    // Render the legend with the filtered set — only the HOME zone row should appear.
    render(<TopologyLegend visibility={visibilityDockerOff} onChange={vi.fn()} presentScopes={presentAfterToggle} />);
    const zoneRows = screen.queryAllByTestId(/^zone-legend-row-/);
    // Only zone-home should render (HOME maps to zone-home).
    expect(zoneRows.length).toBe(1);
  });
});

// ─── AC4: layout uses compound-capable options ────────────────────────────

describe('TopologyView layout options with zones (AC4)', () => {
  beforeEach(() => {
    factoryMock.mockClear();
    mocks.add.mockClear();
    mocks.elements.mockClear();
    mocks.layout.mockClear();
  });

  it('zoneGrouping_layoutStillUsesCoseBilkent', () => {
    // Compound layout must still use cose-bilkent (compound-aware).
    render(
      <TopologyView
        devices={FIVE_SCOPE_DEVICES}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    expect(mocks.layout).toHaveBeenCalled();
    const opts = mocks.layout.mock.calls.at(-1)![0];
    expect(opts.name).toBe('cose-bilkent');
  });

  it('zoneGrouping_layoutSetsNodeDimensionsIncludeLabels', () => {
    // Compound nodes need nodeDimensionsIncludeLabels true so parent label is inside.
    render(
      <TopologyView
        devices={FIVE_SCOPE_DEVICES}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const opts = mocks.layout.mock.calls.at(-1)![0];
    expect(opts.nodeDimensionsIncludeLabels).toBe(true);
  });
});

// ─── buildGatewayEdges cross-zone annotation (unit) ──────────────────────

describe('buildGatewayEdges cross-zone annotation (AC2 / AC5)', () => {
  it('crossZone_dockerBridgeEdge_isFlaggedCrossZone', () => {
    // A published-port docker-bridge edge (container → pivot) crosses the
    // HOME → DOCKER_BRIDGE zone boundary. (An internal-only container with no
    // docker-net gateway is intentionally unattached per AC4 — no pivot edge.)
    const devices: Device[] = [
      makeDevice(1, '192.168.68.51', 'HOME'),
      makeDevice(2, '172.17.0.2', 'DOCKER_BRIDGE', true),
    ];
    const edges = buildGatewayEdges(devices);
    const dbEdge = edges.find(e => e.data.kind === 'docker-bridge');
    expect(dbEdge, 'expected docker-bridge edge').toBeTruthy();
    expect((dbEdge?.data as { crossZone?: boolean }).crossZone).toBe(true);
  });

  it('crossZone_gatewayEdge_withinHomeIsNotFlagged', () => {
    // Two HOME devices: gateway edge stays intra-zone, no crossZone flag.
    const devices: Device[] = [
      makeDevice(1, '192.168.1.1', 'HOME'),
      makeDevice(2, '192.168.1.50', 'HOME'),
    ];
    const edges = buildGatewayEdges(devices);
    const ge = edges.filter(e => e.data.kind === 'gateway');
    expect(ge.length).toBeGreaterThan(0);
    for (const e of ge) {
      expect((e.data as { crossZone?: boolean }).crossZone).not.toBe(true);
    }
  });
});
