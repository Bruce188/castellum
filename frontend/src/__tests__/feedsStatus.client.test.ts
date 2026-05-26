import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock useAuth before importing client (which imports clearAuth/getToken from useAuth)
vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.feedsStatus()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('calls GET /api/risk/feeds/status with Authorization header', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          epss: { scoreDate: '2025-01-01', rowCount: 100 },
          kev: { lastIngestedAt: '2025-01-01T00:00:00Z', entryCount: 50 },
          nvd: { lastModified: '2025-01-01T00:00:00Z', rowCount: 42 },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );

    await api.feedsStatus();

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/risk/feeds/status');
    expect((init?.headers as Record<string, string>)?.['Authorization']).toBe('Bearer mock-token');
  });

  it('parses response into epss/kev/nvd shape', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          epss: { scoreDate: '2025-01-01', rowCount: 100 },
          kev: { lastIngestedAt: '2025-01-01T00:00:00Z', entryCount: 50 },
          nvd: { lastModified: '2025-01-01T00:00:00Z', rowCount: 42 },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );

    const result = await api.feedsStatus();

    expect(result.epss.rowCount).toBe(100);
    expect(result.kev.entryCount).toBe(50);
    expect(result.nvd.rowCount).toBe(42);
    expect(typeof result.nvd.rowCount).toBe('number');
    expect(result.nvd.lastModified).toBe('2025-01-01T00:00:00Z');
  });

  it('nvd.lastModified passes through as null when backend returns null', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          epss: { scoreDate: null, rowCount: 0 },
          kev: { lastIngestedAt: null, entryCount: 0 },
          nvd: { lastModified: null, rowCount: 0 },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );

    const result = await api.feedsStatus();
    expect(result.nvd.lastModified).toBeNull();
  });
});
