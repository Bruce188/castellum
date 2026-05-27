import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/react';
import type { Device, DeviceRiskDto } from '../api/types';

// vi.mock is hoisted to module top — declare the mock factory inline so it has no
// outer-scope references. We pull the per-call records out via require() in tests.
vi.mock('cytoscape', () => {
  const destroy = vi.fn();
  const add = vi.fn();
  const remove = vi.fn();
  const removeClass = vi.fn();
  const addClass = vi.fn();
  const forEach = vi.fn();
  // Cytoscape Collection: cy.elements() returns a Collection that supports
  // .remove(), .removeClass(), .addClass(), .forEach() etc. The path-highlight
  // overlay added in feat/attack-graph-explorer reaches for removeClass/forEach.
  const collection = { remove, removeClass, addClass, forEach };
  const elements = vi.fn(() => collection);
  const nodes = vi.fn(() => collection);
  const edges = vi.fn(() => collection);
  const layoutRun = vi.fn();
  const layout = vi.fn(() => ({ run: layoutRun }));
  const on = vi.fn();
  const factory = vi.fn(() => ({ destroy, add, elements, nodes, edges, layout, on }));
  (factory as unknown as { use: ReturnType<typeof vi.fn> }).use = vi.fn();
  // Expose internals on the factory so tests can read them.
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

const devicesA: Device[] = [
  { id: 1, ipAddress: '10.0.0.1', hostname: 'a', macAddress: null, firstSeen: '2026-01-01T00:00:00Z', lastSeen: '2026-01-01T00:00:00Z', criticality: 'MEDIUM' as const, discoveryScope: 'HOME' as const, lastSeenIface: null, discoverySource: null, serviceCount: 0 },
  { id: 2, ipAddress: '10.0.0.2', hostname: 'b', macAddress: null, firstSeen: '2026-01-01T00:00:00Z', lastSeen: '2026-01-01T00:00:00Z', criticality: 'MEDIUM' as const, discoveryScope: 'HOME' as const, lastSeenIface: null, discoverySource: null, serviceCount: 0 },
];

describe('<TopologyView /> lifecycle', () => {
  beforeEach(() => {
    factoryMock.mockClear();
    mocks.destroy.mockClear();
    mocks.add.mockClear();
    mocks.remove.mockClear();
    mocks.removeClass.mockClear();
    mocks.addClass.mockClear();
    mocks.forEach.mockClear();
    mocks.elements.mockClear();
    mocks.nodes.mockClear();
    mocks.edges.mockClear();
    mocks.layout.mockClear();
    mocks.layoutRun.mockClear();
    mocks.on.mockClear();
  });

  it('topologyView_doesNotCallDestroyOnRiskUpdate', () => {
    const risksA = new Map<number, DeviceRiskDto>();
    const { rerender } = render(
      <TopologyView devices={devicesA} risksById={risksA} onNodeClick={() => {}} onBackgroundClick={() => {}} />
    );
    // First render: cytoscape created exactly once.
    expect(factoryMock).toHaveBeenCalledTimes(1);
    expect(mocks.destroy).not.toHaveBeenCalled();

    // Simulate risk update — new map identity, same devices.
    const risksB = new Map<number, DeviceRiskDto>([[1, { deviceId: 1, score: '4.50', topCveIds: [] }]]);
    rerender(
      <TopologyView devices={devicesA} risksById={risksB} onNodeClick={() => {}} onBackgroundClick={() => {}} />
    );

    // Cytoscape NOT re-created, NOT destroyed mid-life.
    expect(factoryMock).toHaveBeenCalledTimes(1);
    expect(mocks.destroy).not.toHaveBeenCalled();
    // Sync effect should have patched: elements().remove() and add() invoked.
    expect(mocks.elements).toHaveBeenCalled();
    expect(mocks.remove).toHaveBeenCalled();
    expect(mocks.add).toHaveBeenCalled();
  });

  it('topologyView_callsDestroyExactlyOnceOnUnmount', () => {
    const risks = new Map<number, DeviceRiskDto>();
    const { unmount } = render(
      <TopologyView devices={devicesA} risksById={risks} onNodeClick={() => {}} onBackgroundClick={() => {}} />
    );
    expect(mocks.destroy).not.toHaveBeenCalled();
    unmount();
    expect(mocks.destroy).toHaveBeenCalledTimes(1);
  });

  it('topologyView_addsNewElementsViaCyAddOnRiskUpdate', () => {
    const risksA = new Map<number, DeviceRiskDto>();
    const { rerender } = render(
      <TopologyView devices={devicesA} risksById={risksA} onNodeClick={() => {}} onBackgroundClick={() => {}} />
    );
    const addCallsAfterMount = mocks.add.mock.calls.length;

    const risksB = new Map<number, DeviceRiskDto>([[1, { deviceId: 1, score: '8.10', topCveIds: [] }]]);
    rerender(
      <TopologyView devices={devicesA} risksById={risksB} onNodeClick={() => {}} onBackgroundClick={() => {}} />
    );

    // add() invoked at least once more — the patch path used cy.add(), not a fresh cytoscape().
    expect(mocks.add.mock.calls.length).toBeGreaterThan(addCallsAfterMount);
    expect(mocks.layout).toHaveBeenCalled();
    expect(mocks.layoutRun).toHaveBeenCalled();
  });
});
