import { render, act, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
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
    deviceRisksBatch: vi.fn(),
    listScans: vi.fn(),
    listServicesForDevice: vi.fn(),
    feedsStatus: vi.fn(),
    syncStatus: vi.fn(),
    getActiveCidr: vi.fn(),
  },
}));

import { TopologyPage } from '../pages/TopologyPage';
import { api } from '../api/client';

const mockApi = api as unknown as {
  listDevices: ReturnType<typeof vi.fn>;
  deviceRisk: ReturnType<typeof vi.fn>;
  deviceRisksBatch: ReturnType<typeof vi.fn>;
  listScans: ReturnType<typeof vi.fn>;
  listServicesForDevice: ReturnType<typeof vi.fn>;
  feedsStatus: ReturnType<typeof vi.fn>;
  syncStatus: ReturnType<typeof vi.fn>;
  getActiveCidr: ReturnType<typeof vi.fn>;
};

const DEVICES: Device[] = [
  { id: 1, ipAddress: '10.0.0.1', hostname: 'a', macAddress: null, firstSeen: '2026-01-01T00:00:00Z', lastSeen: '2026-01-01T00:00:00Z', criticality: 'MEDIUM', discoveryScope: 'HOME', discoverySource: null, lastSeenIface: null, serviceCount: 0, osName: null, osAccuracy: null, osCpe: null, publishesHostPort: false, deviceRole: 'UNKNOWN', originHostIp: 'local', originHostName: null, networkName: null },
  { id: 2, ipAddress: '10.0.0.2', hostname: 'b', macAddress: null, firstSeen: '2026-01-01T00:00:00Z', lastSeen: '2026-01-01T00:00:00Z', criticality: 'MEDIUM', discoveryScope: 'HOME', discoverySource: null, lastSeenIface: null, serviceCount: 0, osName: null, osAccuracy: null, osCpe: null, publishesHostPort: false, deviceRole: 'UNKNOWN', originHostIp: 'local', originHostName: null, networkName: null },
  { id: 3, ipAddress: '10.0.0.3', hostname: 'c', macAddress: null, firstSeen: '2026-01-01T00:00:00Z', lastSeen: '2026-01-01T00:00:00Z', criticality: 'MEDIUM', discoveryScope: 'HOME', discoverySource: null, lastSeenIface: null, serviceCount: 0, osName: null, osAccuracy: null, osCpe: null, publishesHostPort: false, deviceRole: 'UNKNOWN', originHostIp: 'local', originHostName: null, networkName: null },
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
    localStorage.clear();
    mockApi.listDevices.mockResolvedValue(DEVICES_PAGE);
    mockApi.deviceRisk.mockResolvedValue(RISK);
    mockApi.deviceRisksBatch.mockResolvedValue(
      new Map(DEVICES.map(d => [d.id, RISK]))
    );
    mockApi.listScans.mockResolvedValue(SCANS_PAGE);
    mockApi.listServicesForDevice.mockResolvedValue([]);
    // EmptyCorpusBanner (mounted inside TopologyPage) calls feedsStatus and syncStatus
    mockApi.feedsStatus.mockResolvedValue({
      epss: { scoreDate: '2025-01-01', rowCount: 1000 },
      kev: { lastIngestedAt: '2025-01-01T00:00:00Z', entryCount: 100 },
      nvd: { lastModified: '2025-01-01T00:00:00Z', rowCount: 200000 },
    });
    mockApi.syncStatus.mockResolvedValue({ running: false, startedAt: null });
    // ScanTriggerForm (mounted inside TopologyPage) calls getActiveCidr on mount.
    mockApi.getActiveCidr.mockResolvedValue({ iface: null, cidr: null, ipAddress: null, prefix: 0, note: null });
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

  it('calls api.deviceRisksBatch once with all device ids (no per-device fanout)', async () => {
    render(<TopologyPage />);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    // Single batch call replaces the per-device fanout.
    expect(mockApi.deviceRisksBatch).toHaveBeenCalledTimes(1);
    const calledIds = mockApi.deviceRisksBatch.mock.calls[0][0].slice().sort();
    expect(calledIds).toEqual(DEVICES.map(d => d.id).sort());
  });

  it('surfaces the OT/ICS fingerprint probe in a disclosure on the controls', async () => {
    render(<TopologyPage />);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    // The disclosure summary that reveals the probe (selector disambiguates from
    // OtProbePanel's own <h2> which repeats the label).
    expect(screen.getByText(/OT\/ICS fingerprint probe/i, { selector: 'summary' })).toBeInTheDocument();
    // The reused OtProbePanel itself is mounted (test-id is unique to the panel).
    expect(screen.getByTestId('ot-probe-panel')).toBeInTheDocument();
  });

  describe('scope visibility persistence', () => {
    it('hydrates LOOPBACK=false from localStorage on mount', async () => {
      localStorage.setItem(
        'castellum.topology.scope-visibility',
        JSON.stringify({ HOME: true, DOCKER_BRIDGE: true, LINK_LOCAL: true, LOOPBACK: false, PUBLIC: true }),
      );
      render(<TopologyPage />);
      await act(async () => { await Promise.resolve(); await Promise.resolve(); });
      const loopback = screen.getByRole('checkbox', { name: /LOOPBACK/i });
      expect(loopback).not.toBeChecked();
    });

    it('persists PUBLIC=false to localStorage when toggled', async () => {
      render(<TopologyPage />);
      await act(async () => { await Promise.resolve(); await Promise.resolve(); });
      const publicBox = screen.getByRole('checkbox', { name: /PUBLIC/i });
      fireEvent.click(publicBox);
      const raw = localStorage.getItem('castellum.topology.scope-visibility');
      expect(raw).not.toBeNull();
      const parsed = JSON.parse(raw as string);
      expect(parsed.PUBLIC).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// focus param — R7 feat/device-focus-routing
// ---------------------------------------------------------------------------
// Device 42 used as the focus target. Must appear in the mocked listDevices
// payload so TopologyPage can look it up by id.
const DEVICE_42: Device = {
  id: 42,
  ipAddress: '10.0.0.42',
  hostname: 'focus-host',
  macAddress: null,
  firstSeen: '2026-01-01T00:00:00Z',
  lastSeen: '2026-01-01T00:00:00Z',
  criticality: 'MEDIUM',
  discoveryScope: 'HOME',
  discoverySource: null,
  lastSeenIface: null,
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

const DEVICES_WITH_42: Page<Device> = {
  content: [...DEVICES, DEVICE_42],
  totalElements: DEVICES.length + 1,
  totalPages: 1,
  number: 0,
  size: 200,
};

const RISK_42: DeviceRiskDto = { deviceId: 42, score: '3.00', topCveIds: [] };

describe('<TopologyPage /> ?focus search param — device pre-selection', () => {
  beforeEach(() => {
    localStorage.clear();
    mockApi.listDevices.mockResolvedValue(DEVICES_WITH_42);
    mockApi.deviceRisk.mockResolvedValue(RISK_42);
    mockApi.deviceRisksBatch.mockResolvedValue(
      new Map([...DEVICES, DEVICE_42].map(d => [d.id, RISK_42])),
    );
    mockApi.listScans.mockResolvedValue(SCANS_PAGE);
    mockApi.listServicesForDevice.mockResolvedValue([]);
    mockApi.feedsStatus.mockResolvedValue({
      epss: { scoreDate: '2025-01-01', rowCount: 1000 },
      kev: { lastIngestedAt: '2025-01-01T00:00:00Z', entryCount: 100 },
      nvd: { lastModified: '2025-01-01T00:00:00Z', rowCount: 200000 },
    });
    mockApi.syncStatus.mockResolvedValue({ running: false, startedAt: null });
    mockApi.getActiveCidr.mockResolvedValue({ iface: null, cidr: null, ipAddress: null, prefix: 0, note: null });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('pre-selects the focused device and opens DeviceDetailPanel on load when ?focus=42', async () => {
    render(
      <MemoryRouter initialEntries={['/?focus=42']}>
        <TopologyPage />
      </MemoryRouter>,
    );

    // Flush device + risk fetches.
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    // DeviceDetailPanel should mount showing device 42's hostname.
    await waitFor(() => {
      const panel = screen.getByTestId('device-detail-panel');
      expect(panel).toBeInTheDocument();
      // The panel h2 renders hostname ?? ipAddress — device 42 has hostname 'focus-host'.
      expect(panel.querySelector('h2')?.textContent).toBe('focus-host');
    });
  });

  it('does NOT open DeviceDetailPanel when ?focus param is absent', async () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <TopologyPage />
      </MemoryRouter>,
    );

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    // No focus param → panel should not render (device is null → returns null).
    expect(screen.queryByTestId('device-detail-panel')).not.toBeInTheDocument();
  });

  // ---------------------------------------------------------------------------
  // R7 trip3 nit — focus param change while mounted re-applies to new device
  // (characterization, expected GREEN)
  //
  // FocusParamApplier uses a per-id `appliedRef`: once focus=1 fires it records
  // id=1.  When the URL changes to ?focus=2 (different id), appliedRef.current
  // is 1 ≠ 2 so the effect fires again and selects device 2.  This test locks
  // that re-application behaviour.
  // ---------------------------------------------------------------------------

  it('re-selects device when ?focus param changes to a different id while mounted', async () => {
    // We need a wrapper that can imperatively navigate while keeping the same
    // TopologyPage mounted.  MemoryRouter exposes no navigate ref, so we use a
    // sibling component with useNavigate rendered inside the same MemoryRouter.

    let navigateFn: ((to: string) => void) | null = null;

    function NavigateCapture() {
      const { useNavigate } = require('react-router-dom');
      const navigate = useNavigate();
      // Expose the navigate function to the test scope once on mount
      if (!navigateFn) navigateFn = (to: string) => navigate(to);
      return null;
    }

    // deviceRisksBatch returns risks for all devices (DEVICES already includes device 1)
    mockApi.deviceRisksBatch.mockResolvedValue(
      new Map([...DEVICES, DEVICE_42].map(d => [d.id, RISK_42])),
    );

    render(
      <MemoryRouter initialEntries={['/?focus=42']}>
        <NavigateCapture />
        <TopologyPage />
      </MemoryRouter>,
    );

    // Flush fetches — device 42 should be selected first
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    await waitFor(() => {
      const panel = screen.getByTestId('device-detail-panel');
      expect(panel.querySelector('h2')?.textContent).toBe('focus-host');
    });

    // Now navigate to ?focus=1 (device id 1, hostname 'a')
    await act(async () => {
      navigateFn?.('/?focus=1');
      await Promise.resolve();
    });

    // FocusParamApplier must re-apply: appliedRef was 42, now param is 1 (different id)
    await waitFor(() => {
      const panel = screen.getByTestId('device-detail-panel');
      // Device 1 has hostname 'a' (from DEVICES fixture)
      expect(panel.querySelector('h2')?.textContent).toBe('a');
    });
  });
});
