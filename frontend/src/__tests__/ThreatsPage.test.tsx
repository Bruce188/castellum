import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter } from 'react-router-dom';

// Mock useAuth so each test controls the role independently.
vi.mock('../hooks/useAuth', () => ({
  useAuth: vi.fn(() => ({ token: 'mock-token', roles: [], username: 'viewer' })),
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

vi.mock('../api/client', () => ({
  api: {
    topRisk: vi.fn(),
    feedsStatus: vi.fn(),
    listFleetCves: vi.fn(),
    cveDetail: vi.fn(),
    listAffectedDevices: vi.fn(),
    getDevice: vi.fn(),
    deviceRisk: vi.fn(),
    listServicesForDevice: vi.fn(),
    updateDevice: vi.fn(),
    deleteDevice: vi.fn(),
  },
}));

import { ThreatsPage } from '../pages/ThreatsPage';
import { useAuth } from '../hooks/useAuth';
import { api } from '../api/client';

const makeDevice = (id: number) => ({
  id,
  hostname: `host-${id}`,
  ipAddress: `10.0.0.${id}`,
  macAddress: null,
  criticality: 'HIGH' as const,
  osName: null,
  osAccuracy: null,
  osCpe: null,
  firstSeen: null,
  lastSeen: null,
  lastSeenIface: null,
  serviceCount: 0,
  discoveryScope: 'HOME' as const,
  discoverySource: null,
  deviceRole: 'UNKNOWN' as const,
});

const makeRisk = (deviceId: number) => ({
  deviceId,
  score: '7.50',
  topCveIds: [],
  components: { cvssMax: 7.5, epssMax: 0.1, kevPresent: false, criticalityWeight: 2 },
});

function renderThreatsPage() {
  return render(
    <MemoryRouter initialEntries={['/threats']}>
      <ThreatsPage />
    </MemoryRouter>
  );
}

describe('<ThreatsPage />', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (api.getDevice as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('not mocked'));
    (api.deviceRisk as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('not mocked'));
    (api.listServicesForDevice as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('not mocked'));
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
  });

  it('threatsPage_adminRole_showsDecommissionControl_onRowExpand', async () => {
    // Simulate ADMIN session
    (useAuth as ReturnType<typeof vi.fn>).mockReturnValue({
      token: 'mock-token',
      roles: ['ADMIN'],
      username: 'admin',
    });

    const deviceId = 100;
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId, hostname: `host-${deviceId}`, ipAddress: `10.0.0.${deviceId}`, criticality: 'HIGH', score: '9.00', kevCount: 0 },
    ]);
    (api.getDevice as ReturnType<typeof vi.fn>).mockResolvedValue(makeDevice(deviceId));
    (api.deviceRisk as ReturnType<typeof vi.fn>).mockResolvedValue(makeRisk(deviceId));
    (api.listServicesForDevice as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    renderThreatsPage();

    const row = await screen.findByTestId(`threats-row-${deviceId}`);
    fireEvent.click(row);

    await screen.findByTestId('device-detail-panel');
    expect(screen.getByRole('button', { name: /decommission/i })).toBeInTheDocument();
  });

  it('threatsPage_viewerRole_noDecommissionControl_onRowExpand', async () => {
    // Viewer has no ADMIN role
    (useAuth as ReturnType<typeof vi.fn>).mockReturnValue({
      token: 'mock-token',
      roles: ['VIEWER'],
      username: 'viewer',
    });

    const deviceId = 101;
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId, hostname: `host-${deviceId}`, ipAddress: `10.0.0.${deviceId}`, criticality: 'HIGH', score: '8.00', kevCount: 0 },
    ]);
    (api.getDevice as ReturnType<typeof vi.fn>).mockResolvedValue(makeDevice(deviceId));
    (api.deviceRisk as ReturnType<typeof vi.fn>).mockResolvedValue(makeRisk(deviceId));
    (api.listServicesForDevice as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    renderThreatsPage();

    const row = await screen.findByTestId(`threats-row-${deviceId}`);
    fireEvent.click(row);

    await screen.findByTestId('device-detail-panel');
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: /decommission/i })).toBeNull()
    );
  });
});
