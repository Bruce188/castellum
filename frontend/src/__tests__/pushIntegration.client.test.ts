import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.pushIntegration()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('POSTs /api/integrations/TAXII/push and returns push outcome', async () => {
    const responseBody = {
      status: 'ok',
      bundleId: 'bundle--abc',
      pushedAt: '2026-05-26T01:00:00Z',
      lastPushStatus: 'SUCCESS: status=202',
    };
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(responseBody), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const result = await api.pushIntegration('TAXII');
    expect(result.status).toBe('ok');
    expect(result.bundleId).toBe('bundle--abc');
    expect(result.lastPushStatus).toContain('SUCCESS');

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/integrations/TAXII/push');
    expect(init?.method).toBe('POST');
  });

  it('returns status="error" when backend reports a push failure', async () => {
    const responseBody = {
      status: 'error',
      bundleId: null,
      pushedAt: '2026-05-26T01:01:00Z',
      lastPushStatus: 'ERROR: connection refused',
    };
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(responseBody), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const result = await api.pushIntegration('MISP');
    expect(result.status).toBe('error');
    expect(result.lastPushStatus).toContain('connection refused');
  });
});
