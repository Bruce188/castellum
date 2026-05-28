import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'test-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.probeIntegration()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('(a) 200 → resolves reachable:true and sends Authorization header + url in body', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({ reachable: true, detail: 'ok' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const result = await api.probeIntegration('TAXII', 'http://localhost:9000/');

    expect(result.reachable).toBe(true);

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/integrations/TAXII/probe');
    expect(init?.method).toBe('POST');
    const headers = (init?.headers as Record<string, string>) ?? {};
    expect(headers['Authorization']).toBe('Bearer test-token');
    const bodyParsed = JSON.parse(init?.body as string);
    expect(bodyParsed.url).toBe('http://localhost:9000/');
  });

  it('(a) passes optional collectionId in the request body', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({ reachable: true, detail: 'ok' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    await api.probeIntegration('TAXII', 'http://localhost:9000/', 'enterprise-attack');

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    const bodyParsed = JSON.parse(init?.body as string);
    expect(bodyParsed.collectionId).toBe('enterprise-attack');
  });

  it('(b) 502 → resolves {reachable:false} — does NOT throw', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Bad Gateway', { status: 502 })
    );

    const result = await api.probeIntegration('TAXII', 'http://unreachable.example/');

    expect(result.reachable).toBe(false);
    expect(result).toHaveProperty('detail');
  });

  it('(c) 504 → resolves {reachable:false} — does NOT throw', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Gateway Timeout', { status: 504 })
    );

    const result = await api.probeIntegration('MISP', 'http://slow.example/');

    expect(result.reachable).toBe(false);
    expect(result).toHaveProperty('detail');
  });

  it('(d) network TypeError → resolves {reachable:false} — does NOT throw', async () => {
    vi.spyOn(global, 'fetch').mockRejectedValueOnce(new TypeError('Failed to fetch'));

    const result = await api.probeIntegration('TAXII', 'http://offline.example/');

    expect(result.reachable).toBe(false);
    expect(result).toHaveProperty('detail');
  });

  it('(e) 401 → throws AND clears auth', async () => {
    const useAuthMod = await import('../hooks/useAuth');
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Unauthorized', { status: 401 })
    );

    await expect(
      api.probeIntegration('TAXII', 'http://localhost:9000/')
    ).rejects.toThrow();

    expect(useAuthMod.clearAuth).toHaveBeenCalled();
  });
});
