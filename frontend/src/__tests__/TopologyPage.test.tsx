import { render, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Device, DeviceRiskDto, Page, Scan } from '../api/types';

// Cytoscape mock — TopologyPage indirectly mounts <TopologyView /> which boots
// Cytoscape against a jsdom canvas. Same minimal stub used by
// TopologyViewLifecycle.test.tsx so we don't hit "canvas getContext is null".
vi.mock('cytoscape', () => {
  const noop = vi.fn();
  const collection = { remove: noop, removeClass: noop, addClass: noop, forEach: noop };
  const factory = vi.fn(() => ({
    destroy: noop,
    add: noop,
    elements: () => collection,
    nodes: () => collection,
    edges: () => collection,
    layout: () => ({ run: noop }),
    on: noop,
  }));
  (factory as unknown as { use: ReturnType<typeof vi.fn> }).use = vi.fn();
  return { default: factory };
});
vi.mock('cytoscape-cose-bilkent', () => ({ default: vi.fn() }));

// Mock useAuth so the page sees a logged-in admin token.
vi.mock('../hooks/useAuth', () => ({
  useAuth: () => ({ token: 'mock-token', roles: ['ADMIN'], username: 'admin' }),
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

// Mock the api module so we can count the fanout.
// feedsStatus and syncStatus are called by <EmptyCorpusBanner /> which mounts inside TopologyPage.
vi.mock('../api/client', () => ({
  api: {
    listDevices: vi.fn(),
    deviceRisk: vi.fn(),
    listScans: vi.fn(),
    listServicesForDevice: vi.fn(),
    feedsStatus: vi.fn(),
    syncStatus: vi.fn(),
  },
}));

import { TopologyPage } from '../pages/TopologyPage';
import { api } from '../api/client';

const mockApi = api as unknown as {
  listDevices: ReturnType<typeof vi.fn>;
  deviceRisk: ReturnType<typeof vi.fn>;
  listScans: ReturnType<typeof vi.fn>;
  listServicesForDevice: ReturnType<typeof vi.fn>;
  feedsStatus: ReturnType<typeof vi.fn>;
  syncStatus: ReturnType<typeof vi.fn>;
};

const DEVICES: Device[] = [
  { id: 1, ipAddress: '10.0.0.1', hostname: 'a', macAddress: null, firstSeen: '2026-01-01T00:00:00Z', lastSeen: '2026-01-01T00:00:00Z', criticality: 'MEDIUM', discoveryScope: 'HOME' },
  { id: 2, ipAddress: '10.0.0.2', hostname: 'b', macAddress: null, firstSeen: '2026-01-01T00:00:00Z', lastSeen: '2026-01-01T00:00:00Z', criticality: 'MEDIUM', discoveryScope: 'HOME' },
  { id: 3, ipAddress: '10.0.0.3', hostname: 'c', macAddress: null, firstSeen: '2026-01-01T00:00:00Z', lastSeen: '2026-01-01T00:00:00Z', criticality: 'MEDIUM', discoveryScope: 'HOME' },
];

const DEVICES_PAGE: Page<Device> = {
  content: DEVICES,
  totalElements: DEVICES.length,
  totalPages: 1,
  number: 0,
  size: 200,
};

const SCANS_PAGE: Page<Scan> = {
  content: [],
  totalElements: 0,
  totalPages: 0,
  number: 0,
  size: 1,
};

const RISK: DeviceRiskDto = { deviceId: 1, score: '4.50', topCveIds: [] };

describe('<TopologyPage /> mount fanout', () => {
  beforeEach(() => {
    mockApi.listDevices.mockResolvedValue(DEVICES_PAGE);
    mockApi.deviceRisk.mockResolvedValue(RISK);
    mockApi.listScans.mockResolvedValue(SCANS_PAGE);
    mockApi.listServicesForDevice.mockResolvedValue([]);
    // EmptyCorpusBanner (mounted inside TopologyPage) calls feedsStatus and syncStatus
    mockApi.feedsStatus.mockResolvedValue({
      epss: { scoreDate: '2025-01-01', rowCount: 1000 },
      kev: { lastIngestedAt: '2025-01-01T00:00:00Z', entryCount: 100 },
      nvd: { lastModified: '2025-01-01T00:00:00Z', rowCount: 200000 },
    });
    mockApi.syncStatus.mockResolvedValue({ running: false, startedAt: null });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('calls api.listDevices exactly once on mount', async () => {
    render(<TopologyPage />);
    // flush the queued microtasks for the chained fetch + risk fanout
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(mockApi.listDevices).toHaveBeenCalledTimes(1);
  });

  it('calls api.deviceRisk once per device (no duplicate fanout)', async () => {
    render(<TopologyPage />);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    // Exactly one risk call per device — not 2x because we collapsed the duplicate effect.
    expect(mockApi.deviceRisk).toHaveBeenCalledTimes(DEVICES.length);
    const calledIds = mockApi.deviceRisk.mock.calls.map(call => call[0]).sort();
    expect(calledIds).toEqual(DEVICES.map(d => d.id).sort());
  });
});
