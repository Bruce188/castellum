import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { ScanDetailPage } from '../pages/ScanDetailPage';
import { api } from '../api/client';
import * as scanReportExportModule from '../lib/scanReportExport';
import type { ScanReport } from '../api/types';

vi.mock('../api/client', () => ({
  api: {
    getScanReport: vi.fn(),
  },
}));

vi.mock('../lib/scanReportExport', () => ({
  exportScanReportJson: vi.fn(),
}));

const getScanReport = vi.mocked(api.getScanReport);
const exportScanReportJson = vi.mocked(scanReportExportModule.exportScanReportJson);

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

const baseReport: ScanReport = {
  summary: {
    scanId: 7,
    cidr: '10.0.0.0/24',
    scanType: 'PING_SWEEP',
    status: 'COMPLETE',
    requestedAt: '2024-01-01T00:00:00Z',
    completedAt: '2024-01-01T00:05:00Z',
    durationMillis: 300000,
    retryCount: 0,
    deviceCount: 3,
    serviceCount: 5,
    cveCount: 2,
  },
  devices: [
    {
      id: 101,
      ipAddress: '10.0.0.1',
      hostname: 'host-new',
      delta: 'new',
      services: [{ id: 1, port: 22, protocol: 'tcp', name: 'ssh', version: null }],
      cveIds: ['CVE-2021-1234'],
    },
    {
      id: 102,
      ipAddress: '10.0.0.2',
      hostname: 'host-changed',
      delta: 'changed',
      services: [{ id: 2, port: 80, protocol: 'tcp', name: 'http', version: null }],
      cveIds: ['CVE-2021-5678'],
    },
    {
      id: 103,
      ipAddress: '10.0.0.3',
      hostname: 'host-unchanged',
      delta: 'unchanged',
      services: [],
      cveIds: [],
    },
  ],
};

describe('<ScanDetailPage />', () => {
  beforeEach(() => {
    getScanReport.mockReset();
    exportScanReportJson.mockReset();
    vi.restoreAllMocks();
  });

  it('renders scan heading and CIDR on success', async () => {
    getScanReport.mockResolvedValueOnce(baseReport);
    renderWith('/scans/7');

    expect(await screen.findByText(/Scan #7/)).toBeInTheDocument();
    expect(screen.getByText('10.0.0.0/24')).toBeInTheDocument();
    expect(screen.getByText('COMPLETE')).toBeInTheDocument();
    expect(getScanReport).toHaveBeenCalledWith(7);
  });

  it('renders summary counts and delta badges', async () => {
    getScanReport.mockResolvedValueOnce(baseReport);
    renderWith('/scans/7');

    // Summary counts section must be present
    const countsEl = await screen.findByTestId('scan-summary-counts');
    expect(countsEl).toBeInTheDocument();
    // The element should surface deviceCount / serviceCount / cveCount
    expect(countsEl.textContent).toMatch(/3/);   // deviceCount
    expect(countsEl.textContent).toMatch(/5/);   // serviceCount
    expect(countsEl.textContent).toMatch(/2/);   // cveCount

    // Snapshot table must be present
    const table = await screen.findByTestId('scan-snapshot-table');
    expect(table).toBeInTheDocument();

    // All three delta badges must be rendered
    expect(screen.getByTestId('delta-new')).toBeInTheDocument();
    expect(screen.getByTestId('delta-changed')).toBeInTheDocument();
    expect(screen.getByTestId('delta-unchanged')).toBeInTheDocument();

    // Badge text must match the delta value
    expect(screen.getByTestId('delta-new').textContent).toMatch(/new/i);
    expect(screen.getByTestId('delta-changed').textContent).toMatch(/changed/i);
    expect(screen.getByTestId('delta-unchanged').textContent).toMatch(/unchanged/i);
  });

  it('download JSON button invokes exportScanReportJson with the report', async () => {
    getScanReport.mockResolvedValueOnce(baseReport);
    renderWith('/scans/7');

    const btn = await screen.findByTestId('report-download-json-btn');
    fireEvent.click(btn);

    expect(exportScanReportJson).toHaveBeenCalledTimes(1);
    expect(exportScanReportJson).toHaveBeenCalledWith(baseReport);
  });

  it('print button calls window.print', async () => {
    getScanReport.mockResolvedValueOnce(baseReport);
    const printSpy = vi.spyOn(window, 'print').mockImplementation(() => {});
    renderWith('/scans/7');

    const btn = await screen.findByTestId('report-print-btn');
    fireEvent.click(btn);

    expect(printSpy).toHaveBeenCalledTimes(1);
  });

  it('renders loading state before fetch resolves', () => {
    getScanReport.mockReturnValueOnce(new Promise(() => {}));
    renderWith('/scans/7');
    expect(screen.getByTestId('scan-detail-loading')).toBeInTheDocument();
  });

  it('renders not-found alert with back link on 404', async () => {
    getScanReport.mockRejectedValueOnce(new Error('404 Not Found'));
    renderWith('/scans/9999');
    expect(await screen.findByTestId('scan-detail-not-found')).toBeInTheDocument();
    expect(screen.getByText(/Back to scans/)).toBeInTheDocument();
  });

  it('renders error fallback on non-404 failure', async () => {
    getScanReport.mockRejectedValueOnce(new Error('500 Internal Server Error'));
    renderWith('/scans/7');
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByText(/Back to scans/)).toBeInTheDocument();
  });
});
