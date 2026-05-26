import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.changeUserRole()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('PUTs to /api/users/{u}/role with the new role', async () => {
    const updated = {
      id: 7,
      username: 'alice',
      role: 'ADMIN',
      enabled: true,
      createdAt: null,
      lastLoginAt: null,
    };
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(updated), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const out = await api.changeUserRole('alice', 'ADMIN');

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/users/alice/role');
    expect(init?.method).toBe('PUT');
    expect(JSON.parse(init?.body as string)).toEqual({ role: 'ADMIN' });
    expect(out.role).toBe('ADMIN');
  });

  it('URL-encodes the username', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({}), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );
    await api.changeUserRole('user.name', 'VIEWER');
    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/users/user.name/role');
  });

  it('throws on 403', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Forbidden', { status: 403 })
    );
    await expect(api.changeUserRole('alice', 'ADMIN')).rejects.toThrow('403');
  });
});
