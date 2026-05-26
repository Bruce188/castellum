import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.changePassword()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('POSTs body to /api/auth/change-password and resolves on 204', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(null, { status: 204 })
    );

    await expect(
      api.changePassword({ oldPassword: 'old', newPassword: 'newpassword1' })
    ).resolves.toBeUndefined();

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/auth/change-password');
    expect(init?.method).toBe('POST');
    const body = JSON.parse(init?.body as string);
    expect(body).toEqual({ oldPassword: 'old', newPassword: 'newpassword1' });
    const headers = (init?.headers as Record<string, string>) ?? {};
    expect(headers['Authorization']).toBe('Bearer mock-token');
  });

  it('throws 401-prefixed error on wrong old password', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Unauthorized', { status: 401 })
    );
    await expect(
      api.changePassword({ oldPassword: 'wrong', newPassword: 'newpassword1' })
    ).rejects.toThrow('401 Old password incorrect');
  });

  it('throws 429-prefixed error with retry-after on rate limit', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Too Many Requests', {
        status: 429,
        headers: { 'Retry-After': '45' },
      })
    );
    await expect(
      api.changePassword({ oldPassword: 'old', newPassword: 'newpassword1' })
    ).rejects.toThrow('429 Too Many Requests — retry after 45s');
  });

  it('does not call clearAuth on 401 (caller is authenticated; this is an oldPassword mismatch)', async () => {
    const useAuthMod = await import('../hooks/useAuth');
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Unauthorized', { status: 401 })
    );
    await expect(
      api.changePassword({ oldPassword: 'wrong', newPassword: 'newpassword1' })
    ).rejects.toThrow();
    expect(useAuthMod.clearAuth).not.toHaveBeenCalled();
  });
});
