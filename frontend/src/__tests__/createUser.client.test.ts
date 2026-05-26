import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.createUser()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('POSTs to /api/users and returns the created DTO', async () => {
    const created = {
      id: 7,
      username: 'alice',
      role: 'VIEWER',
      enabled: true,
      createdAt: '2026-05-26T00:00:00Z',
      lastLoginAt: null,
    };
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(created), {
        status: 201,
        headers: { 'content-type': 'application/json' },
      })
    );

    const out = await api.createUser({
      username: 'alice',
      role: 'VIEWER',
      initialPassword: 'initpass1!',
    });

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/users');
    expect(init?.method).toBe('POST');
    const body = JSON.parse(init?.body as string);
    expect(body).toEqual({
      username: 'alice',
      role: 'VIEWER',
      initialPassword: 'initpass1!',
    });
    expect(out.id).toBe(7);
  });

  it('throws 409 on duplicate username', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Conflict', { status: 409 })
    );
    await expect(
      api.createUser({ username: 'alice', role: 'VIEWER', initialPassword: 'initpass1!' })
    ).rejects.toThrow('409 Username already exists');
  });

  it('throws on 403 (VIEWER attempt)', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Forbidden', { status: 403 })
    );
    await expect(
      api.createUser({ username: 'alice', role: 'VIEWER', initialPassword: 'initpass1!' })
    ).rejects.toThrow('403');
  });
});
