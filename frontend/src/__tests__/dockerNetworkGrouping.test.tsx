/**
 * TDD tests for feat/topology-docker-network-grouping (AC1–AC5).
 *
 * Tests cover:
 *   AC1 – nested compound boxes rendered per docker network inside Docker zone.
 *   AC2 – /24-based membership: containers land in the correct network box;
 *          stale/unattached devices land in the fallback box; no crash.
 *   AC3 – per-network gateway edges: 172.20.x container edges to docker-net:supabase,
 *          not docker-net:bridge (existing Step 1+2 /24 grouping already correct).
 *   AC4 – outer zone grouping, attack-path, legend, toggles all preserved.
 *   AC5 – falsifiable unit tests: fixture ≥2 networks, correct membership,
 *          label strips "docker-net:", fallback box for unattached, no empty boxes.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/react';
import type { Device, DiscoveryScope } from '../api/types';

// ─── cytoscape mock (same shape as topologyZoneGrouping.test.tsx) ──────────
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
import {
  buildDockerNetworkGroups,
  isDockerNetGateway,
  dockerNetworkName,
  dockerNetworkGroupId,
  DOCKER_UNATTACHED_GROUP_ID,
  DOCKER_NET_HOSTNAME_PREFIX,
} from '../lib/dockerNetworkGroups';
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
  hostname: string | null = null,
): Device {
  return {
    id,
    ipAddress: ip,
    hostname,
    macAddress: null,
    firstSeen: '2026-01-01T00:00:00Z',
    lastSeen: '2026-01-01T00:00:00Z',
    criticality: 'MEDIUM',
    discoveryScope: scope,
    lastSeenIface: null,
    discoverySource: 'DOCKER' as const,
    serviceCount: 0,
    osName: null,
    osAccuracy: null,
    osCpe: null,
    publishesHostPort: false,
    deviceRole: 'UNKNOWN',
  };
}

// ─── Shared two-network fixture ─────────────────────────────────────────────
// docker-net:supabase_network_supabase gateway at 172.20.0.1 + 2 containers
// docker-net:odisee_network              gateway at 172.21.0.1 + 1 container
// 1 stale ARP entry at 172.18.0.5 (no matching docker-net gateway)
const DOCKER_NET_GW_SUPABASE = makeDevice(100, '172.20.0.1', 'DOCKER_BRIDGE', 'docker-net:supabase_network_supabase');
const DOCKER_NET_GW_ODISEE   = makeDevice(101, '172.21.0.1', 'DOCKER_BRIDGE', 'docker-net:odisee_network');
const SUPABASE_CONTAINER_1   = makeDevice(102, '172.20.0.2', 'DOCKER_BRIDGE', 'supabase-db');
const SUPABASE_CONTAINER_2   = makeDevice(103, '172.20.0.3', 'DOCKER_BRIDGE', 'supabase-api');
const ODISEE_CONTAINER_1     = makeDevice(104, '172.21.0.2', 'DOCKER_BRIDGE', 'odisee-app');
const STALE_ARP              = makeDevice(105, '172.18.0.5', 'DOCKER_BRIDGE', null); // no matching gateway

const TWO_NETWORK_FIXTURE: Device[] = [
  DOCKER_NET_GW_SUPABASE,
  DOCKER_NET_GW_ODISEE,
  SUPABASE_CONTAINER_1,
  SUPABASE_CONTAINER_2,
  ODISEE_CONTAINER_1,
  STALE_ARP,
];

// HOME device (used for cross-zone edge checks and outer zone preservation)
const HOME_DEVICE = makeDevice(1, '192.168.68.1', 'HOME', null);

// ─── AC5 / Unit: dockerNetworkGroups helpers ────────────────────────────────

describe('dockerNetworkGroups helpers (AC5 – unit)', () => {
  it('dockerNet_isDockerNetGateway_returnsTrue_forPrefixedHostname', () => {
    expect(isDockerNetGateway(DOCKER_NET_GW_SUPABASE)).toBe(true);
    expect(isDockerNetGateway(DOCKER_NET_GW_ODISEE)).toBe(true);
  });

  it('dockerNet_isDockerNetGateway_returnsFalse_forContainer', () => {
    expect(isDockerNetGateway(SUPABASE_CONTAINER_1)).toBe(false);
    expect(isDockerNetGateway(STALE_ARP)).toBe(false);
  });

  it('dockerNet_isDockerNetGateway_returnsFalse_forNonDockerScope', () => {
    const homeDevice = makeDevice(1, '192.168.1.1', 'HOME', 'docker-net:fakeout');
    expect(isDockerNetGateway(homeDevice)).toBe(false);
  });

  it('dockerNet_dockerNetworkName_stripsPrefix', () => {
    expect(dockerNetworkName('docker-net:supabase_network_supabase')).toBe('supabase_network_supabase');
    expect(dockerNetworkName('docker-net:bridge')).toBe('bridge');
    expect(dockerNetworkName('docker-net:odisee_network')).toBe('odisee_network');
  });

  it('dockerNet_dockerNetworkName_noop_forNonPrefixed', () => {
    expect(dockerNetworkName('some-container')).toBe('some-container');
  });

  it('dockerNet_dockerNetworkGroupId_returnsStableId', () => {
    expect(dockerNetworkGroupId('bridge')).toBe('docker-net-group-bridge');
    expect(dockerNetworkGroupId('supabase_network_supabase')).toBe('docker-net-group-supabase_network_supabase');
  });

  it('dockerNet_dockerNetworkGroupId_slugifiesUnsafeChars', () => {
    // spaces, dots, hashes in a cytoscape id/selector cause parse errors → must be slugified
    expect(dockerNetworkGroupId('my network')).toBe('docker-net-group-my_network');
    expect(dockerNetworkGroupId('net.work')).toBe('docker-net-group-net_work');
    expect(dockerNetworkGroupId('net#work')).toBe('docker-net-group-net_work');
    // safe chars preserved
    expect(dockerNetworkGroupId('my-net_work')).toBe('docker-net-group-my-net_work');
  });

  it('dockerNet_prefix_constant_is_docker-net-colon', () => {
    expect(DOCKER_NET_HOSTNAME_PREFIX).toBe('docker-net:');
  });
});

// ─── AC2/AC5: buildDockerNetworkGroups membership ──────────────────────────

describe('buildDockerNetworkGroups membership (AC2/AC5)', () => {
  it('dockerNet_twoNetworkFixture_produces_twoNamedGroups_plus_unattached', () => {
    const groups = buildDockerNetworkGroups(TWO_NETWORK_FIXTURE);
    // 2 named networks + 1 unattached = 3 groups
    expect(groups.length).toBe(3);
    const ids = groups.map(g => g.groupId);
    expect(ids).toContain('docker-net-group-supabase_network_supabase');
    expect(ids).toContain('docker-net-group-odisee_network');
    expect(ids).toContain(DOCKER_UNATTACHED_GROUP_ID);
  });

  it('dockerNet_supabaseGroup_containsGatewayAndBothContainers', () => {
    const groups = buildDockerNetworkGroups(TWO_NETWORK_FIXTURE);
    const supabase = groups.find(g => g.groupId === 'docker-net-group-supabase_network_supabase')!;
    expect(supabase).toBeTruthy();
    expect(supabase.memberIds.has(100)).toBe(true); // gateway
    expect(supabase.memberIds.has(102)).toBe(true); // container 1
    expect(supabase.memberIds.has(103)).toBe(true); // container 2
    expect(supabase.memberIds.size).toBe(3);
  });

  it('dockerNet_odiseeGroup_containsGatewayAndOneContainer', () => {
    const groups = buildDockerNetworkGroups(TWO_NETWORK_FIXTURE);
    const odisee = groups.find(g => g.groupId === 'docker-net-group-odisee_network')!;
    expect(odisee).toBeTruthy();
    expect(odisee.memberIds.has(101)).toBe(true); // gateway
    expect(odisee.memberIds.has(104)).toBe(true); // container
    expect(odisee.memberIds.size).toBe(2);
  });

  it('dockerNet_unattachedGroup_containsStaleARP', () => {
    const groups = buildDockerNetworkGroups(TWO_NETWORK_FIXTURE);
    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID)!;
    expect(unattached).toBeTruthy();
    expect(unattached.memberIds.has(105)).toBe(true); // stale ARP
    expect(unattached.memberIds.size).toBe(1);
  });

  it('dockerNet_unattachedGroup_label_is_readable', () => {
    const groups = buildDockerNetworkGroups(TWO_NETWORK_FIXTURE);
    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID)!;
    expect(unattached.label).toContain('unattach');
  });

  it('dockerNet_labels_strip_docker-net-prefix', () => {
    const groups = buildDockerNetworkGroups(TWO_NETWORK_FIXTURE);
    const named = groups.filter(g => g.groupId !== DOCKER_UNATTACHED_GROUP_ID);
    for (const g of named) {
      expect(g.label, `label "${g.label}" must not start with "docker-net:"`).not.toMatch(/^docker-net:/);
    }
    // Labels should equal the bare network name
    const labels = named.map(g => g.label).sort();
    expect(labels).toEqual(['odisee_network', 'supabase_network_supabase'].sort());
  });

  it('dockerNet_noDockerDevices_returnsEmptyGroups', () => {
    const homeOnly = [makeDevice(1, '192.168.1.1', 'HOME')];
    expect(buildDockerNetworkGroups(homeOnly)).toHaveLength(0);
  });

  it('dockerNet_noGatewayNodes_allContainersInUnattached', () => {
    // Containers but no docker-net gateways → all unattached
    const devices = [
      makeDevice(1, '172.17.0.2', 'DOCKER_BRIDGE', null),
      makeDevice(2, '172.17.0.3', 'DOCKER_BRIDGE', 'my-container'),
    ];
    const groups = buildDockerNetworkGroups(devices);
    expect(groups.length).toBe(1);
    expect(groups[0].groupId).toBe(DOCKER_UNATTACHED_GROUP_ID);
    expect(groups[0].memberIds.has(1)).toBe(true);
    expect(groups[0].memberIds.has(2)).toBe(true);
  });

  it('dockerNet_emptyNetworkBoxesOmitted', () => {
    // A gateway-only network (no containers) still has the gateway in its group → not empty.
    // Test: a network with ONLY the gateway device counts as having 1 member, not empty.
    const devices = [
      makeDevice(10, '172.20.0.1', 'DOCKER_BRIDGE', 'docker-net:lonely_network'),
    ];
    const groups = buildDockerNetworkGroups(devices);
    expect(groups.length).toBe(1); // gateway-only group still included
    expect(groups[0].memberIds.has(10)).toBe(true);
  });

  it('dockerNet_crossNetworkContaminationImpossible', () => {
    // Supabase containers must NOT appear in odisee group and vice versa
    const groups = buildDockerNetworkGroups(TWO_NETWORK_FIXTURE);
    const supabase = groups.find(g => g.groupId === 'docker-net-group-supabase_network_supabase')!;
    const odisee   = groups.find(g => g.groupId === 'docker-net-group-odisee_network')!;
    // No cross-contamination
    expect(supabase.memberIds.has(101)).toBe(false); // odisee gateway not in supabase
    expect(supabase.memberIds.has(104)).toBe(false); // odisee container not in supabase
    expect(odisee.memberIds.has(100)).toBe(false);   // supabase gateway not in odisee
    expect(odisee.memberIds.has(102)).toBe(false);   // supabase container not in odisee
    expect(odisee.memberIds.has(103)).toBe(false);
  });
});

// ─── AC3: per-network gateway edge attachment ───────────────────────────────

describe('buildGatewayEdges per-network attachment (AC3)', () => {
  it('dockerNet_supabaseContainer_edgesToSupabaseGateway_notBridgeGateway', () => {
    // 172.20.x containers → docker-net:supabase_network_supabase (172.20.0.1), id=100
    // docker-net:bridge would be at 172.17.0.1 if it existed — it must NOT attract 172.20.x traffic
    const devices: Device[] = [
      DOCKER_NET_GW_SUPABASE, // 172.20.0.1, id=100
      SUPABASE_CONTAINER_1,   // 172.20.0.2, id=102
      SUPABASE_CONTAINER_2,   // 172.20.0.3, id=103
    ];
    const edges = buildGatewayEdges(devices);
    const gatewayEdges = edges.filter(e => e.data.kind === 'gateway');
    // Both containers should edge to the supabase gateway (id=100)
    expect(gatewayEdges.length).toBe(2);
    for (const e of gatewayEdges) {
      expect(e.data.target).toBe('100'); // supabase gateway
    }
  });

  it('dockerNet_odiseeContainer_edgesToOdiseeGateway', () => {
    const devices: Device[] = [
      DOCKER_NET_GW_ODISEE, // 172.21.0.1, id=101
      ODISEE_CONTAINER_1,   // 172.21.0.2, id=104
    ];
    const edges = buildGatewayEdges(devices);
    const gatewayEdges = edges.filter(e => e.data.kind === 'gateway');
    expect(gatewayEdges.length).toBe(1);
    expect(gatewayEdges[0].data.target).toBe('101');
  });

  it('dockerNet_multiNetwork_noContainerEdgesAcrossNetworks', () => {
    // Containers in 172.20.x must not get edges to 172.21.0.1 and vice versa
    const edges = buildGatewayEdges(TWO_NETWORK_FIXTURE);
    const gatewayEdges = edges.filter(e => e.data.kind === 'gateway');
    const supabaseContainerIds = new Set(['102', '103']);
    const odiseeContainerIds   = new Set(['104']);
    for (const e of gatewayEdges) {
      if (supabaseContainerIds.has(e.data.source)) {
        expect(e.data.target).toBe('100'); // must go to supabase GW
      }
      if (odiseeContainerIds.has(e.data.source)) {
        expect(e.data.target).toBe('101'); // must go to odisee GW
      }
    }
  });
});

// ─── AC1: TopologyView renders network sub-box compound nodes ───────────────

describe('TopologyView docker-network sub-box compound nodes (AC1)', () => {
  beforeEach(() => {
    factoryMock.mockClear();
    mocks.add.mockClear();
    mocks.elements.mockClear();
    mocks.layout.mockClear();
  });

  it('dockerNet_twoNetworks_rendersAtLeastTwoNetworkSubBoxes', () => {
    render(
      <TopologyView
        devices={TWO_NETWORK_FIXTURE}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; zone?: boolean; dockerNetwork?: boolean; parent?: string };
    }>;
    // Network sub-boxes carry data.dockerNetwork === true
    const networkBoxes = addArgs.filter(e => e.data.dockerNetwork === true);
    expect(networkBoxes.length, 'expected ≥2 docker-network sub-box compound nodes').toBeGreaterThanOrEqual(2);
  });

  it('dockerNet_networkBoxes_haveParent_zoneDocker', () => {
    render(
      <TopologyView
        devices={TWO_NETWORK_FIXTURE}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; dockerNetwork?: boolean; parent?: string };
    }>;
    const networkBoxes = addArgs.filter(e => e.data.dockerNetwork === true);
    for (const box of networkBoxes) {
      expect(box.data.parent, `network box ${box.data.id} must have parent=zone-docker`).toBe('zone-docker');
    }
  });

  it('dockerNet_containerNodes_haveParent_theirNetworkGroup', () => {
    render(
      <TopologyView
        devices={TWO_NETWORK_FIXTURE}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; parent?: string; zone?: boolean; dockerNetwork?: boolean; source?: string; target?: string };
    }>;
    // Supabase containers (ids 102, 103) must parent to the supabase network box
    const supabaseBox = 'docker-net-group-supabase_network_supabase';
    const odiseeBox   = 'docker-net-group-odisee_network';
    const byId = (id: string) => addArgs.find(e => e.data.id === id && !('source' in e.data));

    expect(byId('102')?.data.parent).toBe(supabaseBox);
    expect(byId('103')?.data.parent).toBe(supabaseBox);
    expect(byId('104')?.data.parent).toBe(odiseeBox);
    // Gateway nodes also belong to their own network box
    expect(byId('100')?.data.parent).toBe(supabaseBox);
    expect(byId('101')?.data.parent).toBe(odiseeBox);
  });

  it('dockerNet_staleDevice_landsInUnattachedBox', () => {
    render(
      <TopologyView
        devices={TWO_NETWORK_FIXTURE}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; parent?: string; source?: string };
    }>;
    const staleNode = addArgs.find(e => e.data.id === '105' && !('source' in e.data));
    expect(staleNode, 'stale ARP device must be in the elements list').toBeTruthy();
    // Must NOT parent directly to zone-docker (would bypass the sub-box level)
    expect(staleNode?.data.parent).not.toBe('zone-docker');
    // Must parent to the unattached sub-box
    expect(staleNode?.data.parent).toBe(DOCKER_UNATTACHED_GROUP_ID);
  });

  it('dockerNet_boxLabels_stripDockerNetPrefix', () => {
    render(
      <TopologyView
        devices={TWO_NETWORK_FIXTURE}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; label?: string; dockerNetwork?: boolean };
    }>;
    const networkBoxes = addArgs.filter(e => e.data.dockerNetwork === true);
    for (const box of networkBoxes) {
      expect(
        box.data.label,
        `network box label "${box.data.label}" must not start with "docker-net:"`
      ).not.toMatch(/^docker-net:/);
    }
  });

  it('dockerNet_gatewayLeafNode_label_doesNotStartWithDockerNetPrefix', () => {
    // NB1 regression guard: the gateway leaf node's display label must not start
    // with "docker-net:" — the raw hostname must be stripped before rendering.
    render(
      <TopologyView
        devices={TWO_NETWORK_FIXTURE}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; label?: string; source?: string };
    }>;
    // Gateway device ids are 100 (supabase) and 101 (odisee)
    for (const gwId of ['100', '101']) {
      const gwNode = addArgs.find(e => e.data.id === gwId && !('source' in e.data));
      expect(gwNode, `gateway node id=${gwId} must appear in elements`).toBeTruthy();
      expect(
        gwNode?.data.label,
        `gateway leaf label "${gwNode?.data.label}" must not start with "docker-net:"`
      ).not.toMatch(/^docker-net:/);
    }
  });
});

// ─── AC4: outer zone grouping preserved when docker-network grouping present ─

describe('TopologyView outer zone preserved with docker-network nesting (AC4)', () => {
  beforeEach(() => {
    factoryMock.mockClear();
    mocks.add.mockClear();
    mocks.elements.mockClear();
    mocks.layout.mockClear();
  });

  it('dockerNet_outerZoneNode_zone-docker_stillPresent', () => {
    const devices: Device[] = [HOME_DEVICE, ...TWO_NETWORK_FIXTURE];
    render(
      <TopologyView
        devices={devices}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; zone?: boolean };
    }>;
    const zoneDocker = addArgs.find(e => e.data.id === 'zone-docker' && e.data.zone === true);
    expect(zoneDocker, 'zone-docker compound node must still be present').toBeTruthy();
  });

  it('dockerNet_outerZoneNode_zone-home_stillPresent', () => {
    const devices: Device[] = [HOME_DEVICE, ...TWO_NETWORK_FIXTURE];
    render(
      <TopologyView
        devices={devices}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; zone?: boolean };
    }>;
    const zoneHome = addArgs.find(e => e.data.id === 'zone-home' && e.data.zone === true);
    expect(zoneHome, 'zone-home compound node must still be present').toBeTruthy();
  });

  it('dockerNet_homeDevice_parentsTo_zone-home_notDockerNetwork', () => {
    const devices: Device[] = [HOME_DEVICE, DOCKER_NET_GW_SUPABASE];
    render(
      <TopologyView
        devices={devices}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; parent?: string; source?: string };
    }>;
    const homeNode = addArgs.find(e => e.data.id === '1' && !('source' in e.data));
    expect(homeNode?.data.parent).toBe('zone-home');
  });

  it('dockerNet_layoutStillUsesCoseBilkent', () => {
    render(
      <TopologyView
        devices={[HOME_DEVICE, ...TWO_NETWORK_FIXTURE]}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const opts = mocks.layout.mock.calls.at(-1)![0];
    expect(opts.name).toBe('cose-bilkent');
  });

  it('dockerNet_nonDockerScopesUnaffectedByDockerNetGrouping', () => {
    // PUBLIC scope device must still parent to zone-public, not any docker sub-box
    const publicDevice = makeDevice(200, '8.8.8.8', 'PUBLIC', null);
    render(
      <TopologyView
        devices={[publicDevice, ...TWO_NETWORK_FIXTURE]}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{
      data: { id: string; parent?: string; source?: string };
    }>;
    const pubNode = addArgs.find(e => e.data.id === '200' && !('source' in e.data));
    expect(pubNode?.data.parent).toBe('zone-public');
  });
});
