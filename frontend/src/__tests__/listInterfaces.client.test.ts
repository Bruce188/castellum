import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.listInterfaces()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('GETs /api/discovery/interfaces with the bearer token', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify([{ name: 'eth0', displayName: 'eth0', mtu: 1500 }]),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );

    const out = await api.listInterfaces();

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/discovery/interfaces');
    expect(init?.method ?? 'GET').toBe('GET');
    expect((init?.headers as Record<string, string>)?.['Authorization']).toBe('Bearer mock-token');
    expect(out).toEqual([{ name: 'eth0', displayName: 'eth0', mtu: 1500 }]);
  });

  it('returns an empty list on 403 (VIEWER) instead of throwing', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Forbidden', { status: 403 })
    );
    await expect(api.listInterfaces()).resolves.toEqual([]);
  });

  it('throws on 500 so the caller can surface the error', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('boom', { status: 500 })
    );
    await expect(api.listInterfaces()).rejects.toThrow('500');
  });
});
