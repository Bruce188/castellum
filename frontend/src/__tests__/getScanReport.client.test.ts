import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';
import type { ScanReport } from '../api/types';

// Minimal fixture that mirrors ScanReportDto exactly (field names must match the
// Java record field names: scanId, cidr, scanType, status, requestedAt, completedAt,
// durationMillis, failureReason, retryCount, deviceCount, serviceCount, cveCount).
const mockReport: ScanReport = {
  summary: {
    scanId: 7,
    cidr: '192.168.1.0/24',
    scanType: 'SERVICE_DETECT',
    status: 'COMPLETE',
    requestedAt: '2024-01-01T10:00:00Z',
    completedAt: '2024-01-01T10:05:00Z',
    durationMillis: 300000,
    failureReason: null,
    retryCount: 0,
    deviceCount: 2,
    serviceCount: 5,
    cveCount: 3,
  },
  devices: [
    {
      id: 1,
      ipAddress: '192.168.1.10',
      hostname: 'host-a',
      delta: 'new',
      services: [
        { id: 11, port: 22, protocol: 'tcp', name: 'ssh', version: 'OpenSSH_8.9' },
      ],
      cveIds: ['CVE-2023-0001'],
    },
    {
      id: 2,
      ipAddress: '192.168.1.20',
      hostname: null,
      delta: 'unchanged',
      services: [],
      cveIds: [],
    },
  ],
};

describe('api.getScanReport()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('GETs /api/scans/7/report with Authorization header and returns parsed ScanReport', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(mockReport), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const result = await api.getScanReport(7);

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    // Falsifiable: wrong URL fails this
    expect(url).toContain('/api/scans/7/report');
    // Falsifiable: missing auth header fails this
    expect((init?.headers as Record<string, string>)?.['Authorization']).toBe('Bearer mock-token');
    // Method should be GET (or undefined, which defaults to GET)
    expect(init?.method ?? 'GET').toBe('GET');

    // Shape assertions — summary fields
    expect(result.summary.scanId).toBe(7);
    expect(result.summary.cidr).toBe('192.168.1.0/24');
    expect(result.summary.scanType).toBe('SERVICE_DETECT');
    expect(result.summary.status).toBe('COMPLETE');
    expect(result.summary.deviceCount).toBe(2);
    expect(result.summary.serviceCount).toBe(5);
    expect(result.summary.cveCount).toBe(3);
    expect(result.summary.durationMillis).toBe(300000);

    // Delta typing — 'new' and 'unchanged' are valid ScanDelta values
    expect(result.devices[0].delta).toBe('new');
    expect(result.devices[1].delta).toBe('unchanged');

    // Nested service shape
    expect(result.devices[0].services[0].port).toBe(22);
    expect(result.devices[0].services[0].protocol).toBe('tcp');

    // cveIds array
    expect(result.devices[0].cveIds).toContain('CVE-2023-0001');
  });

  it('returns a report with delta="changed" device correctly typed', async () => {
    const reportWithChanged: ScanReport = {
      ...mockReport,
      devices: [{ ...mockReport.devices[0], delta: 'changed' }],
    };
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(reportWithChanged), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const result = await api.getScanReport(7);
    expect(result.devices[0].delta).toBe('changed');
  });

  it('throws on 500', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValue(
      new Response('Internal Server Error', { status: 500 })
    );
    await expect(api.getScanReport(7)).rejects.toThrow('500');
  });

  it('clears auth on 401', async () => {
    const useAuthMod = await import('../hooks/useAuth');
    vi.spyOn(global, 'fetch').mockResolvedValue(
      new Response('Unauthorized', { status: 401 })
    );
    await expect(api.getScanReport(7)).rejects.toThrow();
    expect(useAuthMod.clearAuth).toHaveBeenCalled();
  });

  it('uses the scan id in the URL — wrong id produces wrong URL', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(mockReport), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    await api.getScanReport(42);
    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/scans/42/report');
    expect(url).not.toContain('/api/scans/7/report');
  });
});
