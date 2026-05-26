import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.exportStixBundle()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('POSTs /api/threat-intel/export and returns a Blob on 200', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({ type: 'bundle', id: 'bundle--xyz' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const blob = await api.exportStixBundle();
    // Vitest's jsdom Blob is a structurally-compatible class — assert by shape.
    expect(blob).toBeDefined();
    expect(blob.size).toBeGreaterThan(0);
    expect(typeof blob.text).toBe('function');

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/threat-intel/export');
    expect(init?.method).toBe('POST');
    const headers = (init?.headers as Record<string, string>) ?? {};
    expect(headers['Authorization']).toBe('Bearer mock-token');
  });

  it('throws on non-2xx', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Server Error', { status: 500 })
    );
    await expect(api.exportStixBundle()).rejects.toThrow();
  });

  it('clears auth on 401', async () => {
    const useAuthMod = await import('../hooks/useAuth');
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Unauthorized', { status: 401 })
    );
    await expect(api.exportStixBundle()).rejects.toThrow();
    expect(useAuthMod.clearAuth).toHaveBeenCalled();
  });
});
