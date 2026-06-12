import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render } from '@testing-library/react';
import type { Device, DeviceRiskDto } from '../api/types';

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
  add: ReturnType<typeof vi.fn>;
};
const factoryMock = cytoscape as unknown as ReturnType<typeof vi.fn> & { __mocks: MockBag };
const mocks = factoryMock.__mocks;

const PLACEHOLDER = 'mac:aa-bb-cc-dd-ee-ff';

function makeDevice(id: number, ip: string, hostname: string | null): Device {
  return {
    id, ipAddress: ip, hostname, macAddress: null,
    firstSeen: '2026-01-01T00:00:00Z', lastSeen: '2026-01-01T00:00:00Z',
    criticality: 'MEDIUM', discoveryScope: 'HOME',
    lastSeenIface: null,
    discoverySource: null,
    serviceCount: 0,
    osName: null,
    osAccuracy: null,
    osCpe: null,
    publishesHostPort: false,
    deviceRole: 'UNKNOWN',
    originHostIp: 'local',
    originHostName: null,
    networkName: null,
  };
}

describe('<TopologyView /> MAC-placeholder IP rendering', () => {
  beforeEach(() => {
    factoryMock.mockClear();
    mocks.add.mockClear();
  });

  it('sets the node data ip field to "no IP" for a placeholder device, never the raw mac: string', () => {
    const devices: Device[] = [
      makeDevice(1, '192.168.68.50', 'h1'),
      // LLDP MAC-only neighbor: sysname known, no management IP — placeholder key.
      makeDevice(7, PLACEHOLDER, 'lldp-switch'),
    ];
    render(
      <TopologyView
        devices={devices}
        risksById={new Map<number, DeviceRiskDto>()}
        onNodeClick={() => {}}
        onBackgroundClick={() => {}}
      />
    );

    expect(mocks.add).toHaveBeenCalled();
    const addArgs = mocks.add.mock.calls[mocks.add.mock.calls.length - 1][0] as Array<{
      data: { id: string; ip?: string; label?: string };
    }>;

    const placeholderNode = addArgs.find(e => e.data.id === '7');
    expect(placeholderNode).toBeDefined();
    expect(placeholderNode!.data.ip).toBe('no IP');

    // Normal device keeps its real IP in the ip field.
    const normalNode = addArgs.find(e => e.data.id === '1');
    expect(normalNode).toBeDefined();
    expect(normalNode!.data.ip).toBe('192.168.68.50');

    // The raw placeholder string leaks nowhere into the graph payload
    // (labels, ip fields, zone nodes, edges).
    expect(JSON.stringify(addArgs)).not.toContain(PLACEHOLDER);
  });
});
