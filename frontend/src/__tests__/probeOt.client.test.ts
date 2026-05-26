import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.probeOt()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('POSTs the request to /api/ot-probe', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          host: '127.0.0.1',
          port: 502,
          protocol: 'MODBUS_TCP',
          vendor: 'Castellum',
          product: 'MOCK',
          version: '1.0',
          rawFields: { '0': 'Castellum' },
          deviceId: 11,
          serviceId: 22,
          observedAt: '2026-05-26T12:00:00Z',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );

    const out = await api.probeOt({ host: '127.0.0.1', port: 502, protocol: 'MODBUS_TCP' });

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/ot-probe');
    expect(init?.method).toBe('POST');
    const body = JSON.parse(init?.body as string);
    expect(body).toEqual({ host: '127.0.0.1', port: 502, protocol: 'MODBUS_TCP' });
    expect(out.vendor).toBe('Castellum');
    expect(out.deviceId).toBe(11);
  });

  it('throws on 403 (VIEWER attempt)', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Forbidden', { status: 403 })
    );
    await expect(
      api.probeOt({ host: '127.0.0.1', port: 502, protocol: 'MODBUS_TCP' })
    ).rejects.toThrow('403');
  });

  it('throws on 502 (unreachable) — after the bounded single retry surfaces', async () => {
    // The shared request() helper retries once on 502/503/504. Both attempts
    // must fail for the user-visible error to surface — mock two responses.
    const mockFetch = vi.spyOn(global, 'fetch')
      .mockResolvedValueOnce(new Response('Bad Gateway', { status: 502 }))
      .mockResolvedValueOnce(new Response('Bad Gateway', { status: 502 }));
    await expect(
      api.probeOt({ host: '127.0.0.1', port: 502, protocol: 'MODBUS_TCP' })
    ).rejects.toThrow('502');
    expect(mockFetch).toHaveBeenCalledTimes(2);
  }, 10_000);
});
