import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.triggerInitialSync()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('posts to /api/admin/initial-sync with no body (empty object)', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({ status: 'started', startedAt: '2026-01-01T00:00:00Z' }),
        { status: 202, headers: { 'content-type': 'application/json' } }
      )
    );

    const result = await api.triggerInitialSync();

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/admin/initial-sync');
    expect(init?.method).toBe('POST');
    expect(result.status).toBe('started');
    expect(result.startedAt).toBe('2026-01-01T00:00:00Z');
  });

  it('includes explicit window in body', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({ status: 'started', startedAt: '2026-01-01T00:00:00Z' }),
        { status: 202, headers: { 'content-type': 'application/json' } }
      )
    );

    await api.triggerInitialSync({ since: '2024-01-01T00:00:00Z' });

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init?.body as string);
    expect(body.since).toBe('2024-01-01T00:00:00Z');
  });

  it('throws an Error on 401 response', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Unauthorized', { status: 401, headers: { 'content-type': 'application/json' } })
    );

    // 401 triggers clearAuth + throws in the request helper
    await expect(api.triggerInitialSync()).rejects.toThrow();
  });

  it('throws an Error on 403 response', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Forbidden', { status: 403, headers: { 'content-type': 'application/json' } })
    );

    await expect(api.triggerInitialSync()).rejects.toThrow('403');
  });
});
