import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/react';
import type { Device, DeviceRiskDto, DiscoveryScope } from '../api/types';

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

type MockBag = {
  destroy: ReturnType<typeof vi.fn>;
  add: ReturnType<typeof vi.fn>;
  remove: ReturnType<typeof vi.fn>;
  removeClass: ReturnType<typeof vi.fn>;
  addClass: ReturnType<typeof vi.fn>;
  forEach: ReturnType<typeof vi.fn>;
  elements: ReturnType<typeof vi.fn>;
  nodes: ReturnType<typeof vi.fn>;
  edges: ReturnType<typeof vi.fn>;
  layout: ReturnType<typeof vi.fn>;
  layoutRun: ReturnType<typeof vi.fn>;
  on: ReturnType<typeof vi.fn>;
};
const factoryMock = cytoscape as unknown as ReturnType<typeof vi.fn> & { __mocks: MockBag };
const mocks = factoryMock.__mocks;

import type { DiscoverySource } from '../api/types';

function makeDevice(id: number, ip: string, scope: DiscoveryScope, discoverySource?: DiscoverySource | null, serviceCount = 0): Device {
  return {
    id, ipAddress: ip, hostname: `h${id}`, macAddress: null,
    firstSeen: '2026-01-01T00:00:00Z', lastSeen: '2026-01-01T00:00:00Z',
    criticality: 'MEDIUM', discoveryScope: scope,
    lastSeenIface: null,
    discoverySource: discoverySource ?? null,
    serviceCount,
  };
}

describe('<TopologyView /> window seam', () => {
  beforeEach(() => {
    factoryMock.mockClear();
    mocks.add.mockClear();
    mocks.elements.mockClear();
    mocks.layout.mockClear();
    mocks.layoutRun.mockClear();
  });

  it('topologyView_exposesCytoscapeInstanceOnWindow', () => {
    render(
      <TopologyView
        devices={[makeDevice(1, '10.0.0.1', 'HOME')]}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    expect((window as unknown as { __cytoscape?: unknown }).__cytoscape).toBeTruthy();
  });
});

describe('<TopologyView /> layout options', () => {
  beforeEach(() => {
    factoryMock.mockClear();
    mocks.add.mockClear();
    mocks.elements.mockClear();
    mocks.layout.mockClear();
    mocks.layoutRun.mockClear();
  });

  it('topologyView_layout_usesRandomizeTrue', () => {
    render(
      <TopologyView
        devices={[makeDevice(1, '10.0.0.1', 'HOME'), makeDevice(2, '10.0.0.2', 'HOME')]}
        risksById={new Map()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );
    expect(mocks.layout).toHaveBeenCalled();
    const opts = mocks.layout.mock.calls[mocks.layout.mock.calls.length - 1][0];
    expect(opts.randomize).toBe(true);
    expect(opts.name).toBe('cose-bilkent');
  });
});

describe('<TopologyView /> scope rendering', () => {
  beforeEach(() => {
    factoryMock.mockClear();
    mocks.add.mockClear();
    mocks.elements.mockClear();
    mocks.layout.mockClear();
    mocks.layoutRun.mockClear();
  });

  it('topologyView_appliesScopeBorderClassPerScope', () => {
    const devices: Device[] = [
      makeDevice(1, '192.168.68.50', 'HOME'),
      makeDevice(2, '172.17.0.2', 'DOCKER_BRIDGE'),
      makeDevice(3, '169.254.73.152', 'LINK_LOCAL'),
      makeDevice(4, '127.0.0.1', 'LOOPBACK'),
      makeDevice(5, '8.8.8.8', 'PUBLIC'),
    ];
    render(
      <TopologyView devices={devices} risksById={new Map<number, DeviceRiskDto>()} onNodeClick={() => {}} onBackgroundClick={() => {}} />
    );

    expect(mocks.add).toHaveBeenCalled();
    const addArgs = mocks.add.mock.calls[mocks.add.mock.calls.length - 1][0] as Array<{ data: { id: string }; classes: string }>;
    const byId = (id: string) => addArgs.find(e => e.data.id === id);

    // HOME — no scope-* class, only risk-*
    expect(byId('1')?.classes).toMatch(/^risk-[a-z]+$/);
    expect(byId('1')?.classes).not.toContain('scope-');

    expect(byId('2')?.classes).toContain('scope-docker-bridge');
    expect(byId('3')?.classes).toContain('scope-link-local');
    expect(byId('4')?.classes).toContain('scope-loopback');
    expect(byId('5')?.classes).toContain('scope-public');
  });

  it('topologyView_nodeData_includesServiceCount', () => {
    const devices = [makeDevice(1, '192.168.68.50', 'HOME', 'ARP', 3), makeDevice(2, '10.0.0.1', 'HOME', null, 0)];
    render(
      <TopologyView devices={devices} risksById={new Map<number, DeviceRiskDto>()} onNodeClick={() => {}} onBackgroundClick={() => {}} />
    );
    expect(mocks.add).toHaveBeenCalled();
    const addArgs = mocks.add.mock.calls.at(-1)![0] as Array<{ data: { id: string; serviceCount?: number; label: string } }>;
    const byId = (id: string) => addArgs.find(e => e.data.id === id);
    expect(byId('1')?.data.serviceCount).toBe(3);
    expect(byId('1')?.data.label).toContain('3 svc');
    expect(byId('2')?.data.serviceCount).toBe(0);
  });

  it('topologyView_nodeData_includesDiscoverySource', () => {
    const devices: Device[] = [
      makeDevice(1, '192.168.68.50', 'HOME', 'ARP'),
      makeDevice(2, '10.0.0.1', 'HOME', null),
    ];
    render(
      <TopologyView devices={devices} risksById={new Map<number, DeviceRiskDto>()} onNodeClick={() => {}} onBackgroundClick={() => {}} />
    );

    expect(mocks.add).toHaveBeenCalled();
    const addArgs = mocks.add.mock.calls[mocks.add.mock.calls.length - 1][0] as Array<{ data: { id: string; discoverySource?: string | null } }>;
    const byId = (id: string) => addArgs.find(e => e.data.id === id);

    // Device with ARP source — data.discoverySource must be 'ARP'
    expect(byId('1')?.data.discoverySource).toBe('ARP');
    // Device with null source — data.discoverySource must be null (not undefined)
    expect(byId('2')?.data.discoverySource).toBeNull();
  });

  it('topologyView_hidesNodesWhenScopeVisibilityFalse', () => {
    const devices: Device[] = [
      makeDevice(1, '192.168.68.50', 'HOME'),
      makeDevice(2, '127.0.0.1', 'LOOPBACK'),
    ];
    const visibility = {
      HOME: true,
      DOCKER_BRIDGE: true,
      LINK_LOCAL: true,
      LOOPBACK: false,
      PUBLIC: true,
    } as const;

    render(
      <TopologyView
        devices={devices}
        risksById={new Map<number, DeviceRiskDto>()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
        scopeVisibility={visibility}
      />
    );

    expect(mocks.add).toHaveBeenCalled();
    const addArgs = mocks.add.mock.calls[mocks.add.mock.calls.length - 1][0] as Array<{ data: { id: string } }>;
    const nodeIds = addArgs.filter(e => /^\d+$/.test(e.data.id)).map(e => e.data.id);
    expect(nodeIds).toEqual(['1']);
    expect(nodeIds).not.toContain('2');
  });
});
