import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ThreatsDashboard } from '../components/ThreatsDashboard';
import { api } from '../api/client';

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

const PLACEHOLDER = 'mac:aa-bb-cc-dd-ee-ff';

function renderWith() {
  return render(
    <MemoryRouter initialEntries={['/threats']}>
      <ThreatsDashboard />
    </MemoryRouter>
  );
}

describe('<ThreatsDashboard /> MAC-placeholder IP rendering', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: null, rowCount: 0 },
      kev: { lastIngestedAt: null, entryCount: 0 },
      nvd: { lastModified: null, rowCount: 0 },
    });
    (api.getDevice as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('not mocked'));
    (api.deviceRisk as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('not mocked'));
    (api.listServicesForDevice as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('not mocked'));
  });

  it('hostname-less placeholder device renders "no IP" in the host cell, never the raw mac: string', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'host-1', ipAddress: '10.0.0.1', criticality: 'HIGH', score: '8.50', kevCount: 1 },
      { deviceId: 9, hostname: null, ipAddress: PLACEHOLDER, criticality: 'LOW', score: '1.00', kevCount: 0 },
    ]);

    renderWith();
    await screen.findByText('host-1');

    expect(screen.getByText('no IP')).toBeInTheDocument();
    expect(screen.queryByText(PLACEHOLDER)).not.toBeInTheDocument();
    // Normal device IPs are untouched (host-1 has a hostname, so 10.0.0.1 shows in the sub-line).
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument();
  });

  it('hostname-bearing placeholder device renders "no IP" in the IP sub-line, never the raw mac: string', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'host-1', ipAddress: '10.0.0.1', criticality: 'HIGH', score: '8.50', kevCount: 1 },
      { deviceId: 9, hostname: 'lldp-switch', ipAddress: PLACEHOLDER, criticality: 'LOW', score: '1.00', kevCount: 0 },
    ]);

    renderWith();
    await screen.findByText('lldp-switch');

    expect(screen.getByText('no IP')).toBeInTheDocument();
    expect(screen.queryByText(PLACEHOLDER)).not.toBeInTheDocument();
  });
});
