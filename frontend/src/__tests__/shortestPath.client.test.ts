import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.shortestPath()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('GETs /api/graph/shortest-path with the from+to params and returns the response', async () => {
    const payload = {
      from: 1,
      to: 3,
      pathFound: true,
      totalHops: 2,
      cumulativeRisk: '7.50',
      hops: [
        {
          deviceId: 2, ipAddress: '10.0.0.5', edgeType: 'SAME_SUBNET',
          attackTechniqueId: null, attackTechniqueName: null,
          edgeRisk: '1.00', cumulativeRisk: '1.00', cveId: null,
        },
        {
          deviceId: 3, ipAddress: '172.16.0.10', edgeType: 'EXPLOITABLE_VULN',
          attackTechniqueId: 'T1190', attackTechniqueName: 'Exploit Public-Facing Application',
          edgeRisk: '6.50', cumulativeRisk: '7.50', cveId: 'CVE-2024-12345',
        },
      ],
    };
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(payload), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const out = await api.shortestPath({ from: 1, to: 3 });

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/graph/shortest-path?from=1&to=3');
    const headers = init.headers as Record<string, string>;
    expect(headers['Authorization']).toBe('Bearer mock-token');
    expect(out.pathFound).toBe(true);
    expect(out.hops).toHaveLength(2);
    expect(out.hops[1].cveId).toBe('CVE-2024-12345');
    expect(out.hops[1].edgeType).toBe('EXPLOITABLE_VULN');
  });

  it('returns pathFound=false when backend reports no path', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({ from: 1, to: 99, pathFound: false, totalHops: 0, cumulativeRisk: null, hops: [] }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );
    const out = await api.shortestPath({ from: 1, to: 99 });
    expect(out.pathFound).toBe(false);
    expect(out.hops).toEqual([]);
  });

  it('throws on non-2xx', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Bad Request', { status: 400, statusText: 'Bad Request' })
    );
    await expect(api.shortestPath({ from: 1, to: 1 })).rejects.toThrow('400');
  });
});
