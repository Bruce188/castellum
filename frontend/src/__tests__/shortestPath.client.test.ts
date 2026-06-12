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

  describe('non-OK error surfacing', () => {
    it('rejects a 4xx with the HTTP status and NO body — client errors throw before the body is read', async () => {
      vi.spyOn(global, 'fetch').mockResolvedValueOnce(
        new Response(
          JSON.stringify({ error: 'VALIDATION_FAILED', message: 'from and to must differ' }),
          { status: 400, statusText: 'Bad Request', headers: { 'content-type': 'application/json' } }
        )
      );

      const err = await api.shortestPath({ from: 1, to: 1 }).then(
        () => { throw new Error('expected rejection'); },
        (e: unknown) => e as Error & { status?: number; body?: unknown },
      );
      // Canonical `${status} ${statusText}` prefix is preserved — isRetryable()
      // and the existing string-matching callers depend on it.
      expect(err.message).toMatch(/^400/);
      expect(err.status).toBe(400);
      // Body parsing is reserved for >= 500 responses (machine-readable
      // degrade codes); a 4xx rejection carries no body even when the
      // response held parseable JSON.
      expect(err.body).toBeUndefined();
    });

    it('rejects a 404 immediately even when the body stream never resolves', async () => {
      vi.useFakeTimers();
      try {
        const wedged = {
          ok: false,
          status: 404,
          statusText: 'Not Found',
          json: () => new Promise<never>(() => { /* never settles */ }),
        } as unknown as Response;
        vi.spyOn(global, 'fetch').mockResolvedValueOnce(wedged);

        // No timer advancement here: if the 4xx path still raced the wedged
        // body against ERROR_BODY_READ_TIMEOUT_MS, this await would hang to
        // the test timeout instead of settling immediately.
        await expect(api.shortestPath({ from: 1, to: 999 })).rejects.toMatchObject({
          message: expect.stringMatching(/^404/),
          status: 404,
        });
      } finally {
        vi.useRealTimers();
      }
    });

    it('rejects with status 503 and the GRAPH_TOO_LARGE code from the backend 503 body', async () => {
      // Backend contract (GlobalExceptionHandler): HTTP 503 with
      // { error: "GRAPH_TOO_LARGE", message: "device count N exceeds castellum.graph.max-devices=C" }.
      vi.spyOn(global, 'fetch').mockImplementation(async () =>
        new Response(
          JSON.stringify({
            error: 'GRAPH_TOO_LARGE',
            message: 'device count 6200 exceeds castellum.graph.max-devices=5000',
          }),
          { status: 503, statusText: 'Service Unavailable', headers: { 'content-type': 'application/json' } }
        )
      );

      await expect(api.shortestPath({ from: 1, to: 3 })).rejects.toMatchObject({
        message: expect.stringMatching(/^503/),
        status: 503,
        body: {
          error: 'GRAPH_TOO_LARGE',
          message: expect.stringContaining('max-devices'),
        },
      });
    });

    it('still carries the HTTP status when the error body is not JSON', async () => {
      vi.spyOn(global, 'fetch').mockResolvedValueOnce(
        new Response('Not Found', { status: 404, statusText: 'Not Found' })
      );

      await expect(api.shortestPath({ from: 1, to: 999 })).rejects.toMatchObject({
        message: expect.stringMatching(/^404/),
        status: 404,
      });
    });
  });
});
