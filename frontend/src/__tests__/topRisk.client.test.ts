import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.topRisk()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('calls GET /api/risk/top?n=10 by default with Authorization header', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } })
    );

    await api.topRisk();

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/risk/top?n=10');
    expect((init?.headers as Record<string, string>)?.['Authorization']).toBe('Bearer mock-token');
  });

  it('honors explicit n argument', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } })
    );

    await api.topRisk(25);

    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/risk/top?n=25');
  });

  it('parses array of TopRiskDeviceDto', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify([
          {
            deviceId: 1,
            hostname: 'host-1',
            ipAddress: '10.0.0.1',
            criticality: 'HIGH',
            score: '7.50',
            kevCount: 2,
          },
        ]),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );

    const result = await api.topRisk(10);
    expect(result).toHaveLength(1);
    expect(result[0].deviceId).toBe(1);
    expect(result[0].hostname).toBe('host-1');
    expect(result[0].score).toBe('7.50');
    expect(result[0].kevCount).toBe(2);
  });
});

describe('api.cveDetail()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('calls GET /api/cve/{cveId} with URL-encoded id', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          cveId: 'CVE-2020-15778',
          published: '2020-07-20T22:15:00Z',
          lastModified: '2024-01-01T00:00:00Z',
          vulnStatus: 'Analyzed',
          description: 'desc',
          cvssV31Score: '7.8',
          cvssV31Vector: null,
          cvssV30Score: null,
          cvssV30Vector: null,
          cvssV2Score: null,
          cvssV2Vector: null,
          fetchedAt: null,
          rawJson: null,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );

    const result = await api.cveDetail('CVE-2020-15778');

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/cve/CVE-2020-15778');
    expect((init?.headers as Record<string, string>)?.['Authorization']).toBe('Bearer mock-token');
    expect(result.cveId).toBe('CVE-2020-15778');
    expect(result.cvssV31Score).toBe('7.8');
  });
});
