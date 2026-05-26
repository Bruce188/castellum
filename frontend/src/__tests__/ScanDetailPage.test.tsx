import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { ScanDetailPage } from '../pages/ScanDetailPage';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    getScanDetail: vi.fn(),
    getDevice: vi.fn(),
  },
}));

const getScanDetail = vi.mocked(api.getScanDetail);
const getDevice = vi.mocked(api.getDevice);

function renderWith(path = '/scans/7') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/scans/:id" element={<ScanDetailPage />} />
        <Route path="/scans" element={<div>scans list</div>} />
      </Routes>
    </MemoryRouter>
  );
}

describe('<ScanDetailPage />', () => {
  beforeEach(() => {
    getScanDetail.mockReset();
    getDevice.mockReset();
  });

  it('renders scan metadata and discovered devices on success', async () => {
    getScanDetail.mockResolvedValueOnce({
      id: 7,
      cidr: '10.0.0.0/24',
      scanType: 'PING_SWEEP',
      status: 'COMPLETE',
      requestedAt: '2024-01-01T00:00:00Z',
      completedAt: '2024-01-01T00:05:00Z',
      retryCount: 0,
      discoveredDeviceIds: [101, 102],
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any);
    getDevice
      .mockResolvedValueOnce({
        id: 101, ipAddress: '10.0.0.1', hostname: 'host-a',
        macAddress: null, firstSeen: '2024-01-01T00:01:00Z',
        lastSeen: '2024-01-01T00:02:00Z', criticality: 'MEDIUM',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any)
      .mockResolvedValueOnce({
        id: 102, ipAddress: '10.0.0.2', hostname: 'host-b',
        macAddress: null, firstSeen: '2024-01-01T00:03:00Z',
        lastSeen: '2024-01-01T00:04:00Z', criticality: 'MEDIUM',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any);

    renderWith('/scans/7');

    expect(await screen.findByText(/Scan #7/)).toBeInTheDocument();
    expect(screen.getByText('10.0.0.0/24')).toBeInTheDocument();
    expect(screen.getByText('COMPLETE')).toBeInTheDocument();
    expect(await screen.findByText('host-a')).toBeInTheDocument();
    expect(await screen.findByText('host-b')).toBeInTheDocument();
    expect(getScanDetail).toHaveBeenCalledWith(7);
  });

  it('renders "Scan not found" with back link on 404', async () => {
    getScanDetail.mockRejectedValueOnce(new Error('404 Not Found'));
    renderWith('/scans/9999');
    expect(await screen.findByTestId('scan-detail-not-found')).toBeInTheDocument();
    expect(screen.getByText(/Back to scans/)).toBeInTheDocument();
  });

  it('shows loading state before fetch resolves', () => {
    getScanDetail.mockReturnValueOnce(new Promise(() => {}));
    renderWith('/scans/7');
    expect(screen.getByTestId('scan-detail-loading')).toBeInTheDocument();
  });
});
