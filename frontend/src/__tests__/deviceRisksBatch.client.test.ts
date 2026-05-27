import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.deviceRisksBatch()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('builds GET /api/risk/devices?ids=1,2,3 and decodes the object response into a Map', async () => {
    const mockPayload = {
      1: { deviceId: 1, score: '4.50', topCveIds: ['CVE-2024-0001'] },
      2: { deviceId: 2, score: '7.20', topCveIds: [] },
      3: { deviceId: 3, score: '2.10', topCveIds: [] },
    };

    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(mockPayload), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const result = await api.deviceRisksBatch([1, 2, 3]);

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/risk/devices?ids=1,2,3');
    expect(init?.method ?? 'GET').toBe('GET');
    expect((init?.headers as Record<string, string>)?.['Authorization']).toBe('Bearer mock-token');

    expect(result).toBeInstanceOf(Map);
    expect(result.size).toBe(3);
    expect(result.get(1)?.score).toBe('4.50');
    expect(result.get(2)?.score).toBe('7.20');
    expect(result.get(3)?.score).toBe('2.10');
    expect(result.get(1)?.topCveIds).toEqual(['CVE-2024-0001']);
  });

  it('returns an empty Map when ids array is empty (no fetch)', async () => {
    const mockFetch = vi.spyOn(global, 'fetch');

    const result = await api.deviceRisksBatch([]);

    expect(mockFetch).not.toHaveBeenCalled();
    expect(result).toBeInstanceOf(Map);
    expect(result.size).toBe(0);
  });
});
