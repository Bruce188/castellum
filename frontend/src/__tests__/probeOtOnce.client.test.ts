import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

const PROBE_RESPONSE = {
  host: '192.168.1.50',
  port: 502,
  protocol: 'MODBUS_TCP' as const,
  vendor: 'Schneider',
  product: 'M340',
  version: '2.1',
  rawFields: { '0': 'Schneider' },
  deviceId: 5,
  serviceId: 9,
  observedAt: '2026-05-28T10:00:00Z',
};

describe('api.probeOtOnce()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  // (a) passthrough: 200 → returns parsed OtProbeResponse; asserts correct URL, method, body, auth header
  it('(a) 200 → returns parsed OtProbeResponse; POSTs to /api/ot-probe with correct body and Bearer token', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(PROBE_RESPONSE), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const out = await api.probeOtOnce('192.168.1.50', 'MODBUS_TCP', 502);

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/ot-probe');
    expect(init?.method).toBe('POST');

    const body = JSON.parse(init?.body as string);
    expect(body).toEqual({ host: '192.168.1.50', protocol: 'MODBUS_TCP', port: 502 });

    const headers = (init?.headers as Record<string, string>) ?? {};
    expect(headers['Authorization']).toBe('Bearer mock-token');

    expect(out).toEqual(PROBE_RESPONSE);
    expect(out.vendor).toBe('Schneider');
    expect(out.deviceId).toBe(5);
  });

  // (b) non-retry on 5xx (LOAD-BEARING): a single 502 → rejects with '502' AND fetch called EXACTLY ONCE
  //     This is the key anti-retry-amplification property — contrast api.probeOt which retries (2 calls).
  it('(b) 502 → rejects with error containing "502" and fetch is called EXACTLY ONCE (no retry)', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Bad Gateway', { status: 502, statusText: 'Bad Gateway' })
    );

    await expect(
      api.probeOtOnce('192.168.1.50', 'MODBUS_TCP', 502)
    ).rejects.toThrow('502');

    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  // (b) also check 503 — single shot, no retry
  it('(b) 503 → rejects with error containing "503" and fetch is called EXACTLY ONCE (no retry)', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Service Unavailable', { status: 503, statusText: 'Service Unavailable' })
    );

    await expect(
      api.probeOtOnce('192.168.1.50', 'DNP3', 20000)
    ).rejects.toThrow('503');

    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  // (c) 401 → clearAuth invoked + throws containing '401'
  it('(c) 401 → calls clearAuth and throws error containing "401"', async () => {
    const useAuthMod = await import('../hooks/useAuth');
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Unauthorized', { status: 401, statusText: 'Unauthorized' })
    );

    await expect(
      api.probeOtOnce('192.168.1.50', 'S7COMM', 102)
    ).rejects.toThrow('401');

    expect(useAuthMod.clearAuth).toHaveBeenCalled();
  });

  // (c) non-ok non-401 (e.g. 403) → throws with status code, fetch called exactly once
  it('(c) 403 → rejects with "403" and fetch called exactly once (no retry)', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Forbidden', { status: 403, statusText: 'Forbidden' })
    );

    await expect(
      api.probeOtOnce('192.168.1.50', 'BACNET_IP', 47808)
    ).rejects.toThrow('403');

    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  // (d) signal passthrough: a provided AbortSignal is forwarded to fetch init.signal
  it('(d) forwards AbortSignal to fetch init.signal', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(PROBE_RESPONSE), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const controller = new AbortController();
    await api.probeOtOnce('192.168.1.50', 'MODBUS_TCP', 502, controller.signal);

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect((init as RequestInit & { signal?: AbortSignal }).signal).toBe(controller.signal);
  });

  // (d) when no signal is passed, fetch init.signal is absent/undefined
  it('(d) when no signal is passed, fetch is called without a signal', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(PROBE_RESPONSE), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    await api.probeOtOnce('192.168.1.50', 'MODBUS_TCP', 502);

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    const signal = (init as RequestInit & { signal?: AbortSignal }).signal;
    expect(signal == null).toBe(true);
  });
});
