import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.discoverPassive()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('POSTs the request body to /api/discovery/passive', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          discovered: 2,
          deviceIds: [1, 2],
          perSourceCount: { ARP: 2 },
          sweepId: 7,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );

    const out = await api.discoverPassive({
      iface: 'eth0',
      durationSeconds: 30,
      sources: ['ARP', 'MDNS'],
    });

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/discovery/passive');
    expect(init?.method).toBe('POST');
    const body = JSON.parse(init?.body as string);
    expect(body).toEqual({ iface: 'eth0', durationSeconds: 30, sources: ['ARP', 'MDNS'] });
    expect(out.discovered).toBe(2);
    expect(out.sweepId).toBe(7);
  });

  it('throws on 403 (VIEWER attempt)', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Forbidden', { status: 403 })
    );
    await expect(
      api.discoverPassive({ iface: 'eth0', durationSeconds: 30, sources: ['ARP'] })
    ).rejects.toThrow('403');
  });

  it('throws on 401', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Unauthorized', { status: 401 })
    );
    await expect(
      api.discoverPassive({ iface: 'eth0', durationSeconds: 30, sources: ['ARP'] })
    ).rejects.toThrow();
  });
});
