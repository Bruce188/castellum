import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.getActiveCidr()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('GETs /api/discovery/active-cidr with bearer token and returns parsed body', async () => {
    const mockPayload = {
      iface: 'eth6',
      cidr: '192.168.68.0/22',
      ipAddress: '192.168.68.51',
      prefix: 22,
      note: null,
    };

    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(mockPayload), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const result = await api.getActiveCidr();

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/discovery/active-cidr');
    expect(init?.method ?? 'GET').toBe('GET');
    expect((init?.headers as Record<string, string>)?.['Authorization']).toBe('Bearer mock-token');
    expect(result.iface).toBe('eth6');
    expect(result.cidr).toBe('192.168.68.0/22');
    expect(result.ipAddress).toBe('192.168.68.51');
    expect(result.prefix).toBe(22);
  });

  it('returns documented empty shape on 500 without throwing', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Internal Server Error', { status: 500 })
    );

    const result = await api.getActiveCidr();

    expect(result.iface).toBeNull();
    expect(result.cidr).toBeNull();
    expect(result.ipAddress).toBeNull();
    expect(result.prefix).toBe(0);
  });

  it('returns documented empty shape on 403 without throwing', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Forbidden', { status: 403 })
    );

    const result = await api.getActiveCidr();

    expect(result.iface).toBeNull();
    expect(result.cidr).toBeNull();
    expect(result.ipAddress).toBeNull();
    expect(result.prefix).toBe(0);
  });

  it('returns documented empty shape on network error without throwing', async () => {
    // mockRejectedValue (not ...Once): request() retries network errors once, and a
    // single-shot mock would let the retry hit real fetch and hang past the test timeout.
    vi.spyOn(global, 'fetch').mockRejectedValue(new TypeError('network failure'));

    const result = await api.getActiveCidr();

    expect(result.cidr).toBeNull();
    expect(result.prefix).toBe(0);
  });
});
