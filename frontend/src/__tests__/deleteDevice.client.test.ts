import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.deleteDevice()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('DELETEs /api/devices/{id} with Authorization header', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(null, { status: 204 })
    );

    await api.deleteDevice(7);

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/devices/7');
    expect(init?.method).toBe('DELETE');
    expect((init?.headers as Record<string, string>)?.['Authorization']).toBe('Bearer mock-token');
  });

  it('resolves on 204 without parsing JSON', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(new Response(null, { status: 204 }));
    await expect(api.deleteDevice(7)).resolves.toBeUndefined();
  });

  it('throws on 403 (VIEWER attempt)', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Forbidden', { status: 403 })
    );
    await expect(api.deleteDevice(7)).rejects.toThrow('403');
  });

  it('throws on 401', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Unauthorized', { status: 401 })
    );
    await expect(api.deleteDevice(7)).rejects.toThrow();
  });
});
