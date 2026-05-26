import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.listUsers()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('GETs /api/users with page+size+sort and returns the page', async () => {
    const payload = {
      content: [
        { id: 1, username: 'alice', role: 'VIEWER', enabled: true, createdAt: null, lastLoginAt: null },
      ],
      totalElements: 1,
      totalPages: 1,
      number: 0,
      size: 50,
    };
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(payload), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const out = await api.listUsers(0, 50);

    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/users?page=0&size=50&sort=username,asc');
    expect(out.content[0].username).toBe('alice');
    expect(out.totalElements).toBe(1);
  });

  it('throws on 403 (VIEWER attempt)', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Forbidden', { status: 403 })
    );
    await expect(api.listUsers()).rejects.toThrow('403');
  });
});
