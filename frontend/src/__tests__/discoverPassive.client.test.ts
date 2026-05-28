import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.discoverPassive()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('POSTs the request body to /api/discovery/passive', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          discovered: 2,
          deviceIds: [1, 2],
          perSourceCount: { ARP: 2 },
          sweepId: 7,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );

    const out = await api.discoverPassive({
      iface: 'eth0',
      durationSeconds: 30,
      sources: ['ARP', 'MDNS'],
    });

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/discovery/passive');
    expect(init?.method).toBe('POST');
    const body = JSON.parse(init?.body as string);
    expect(body).toEqual({ iface: 'eth0', durationSeconds: 30, sources: ['ARP', 'MDNS'] });
    expect(out.discovered).toBe(2);
    expect(out.sweepId).toBe(7);
  });

  it('throws on 403 (VIEWER attempt)', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Forbidden', { status: 403 })
    );
    await expect(
      api.discoverPassive({ iface: 'eth0', durationSeconds: 30, sources: ['ARP'] })
    ).rejects.toThrow('403');
  });

  it('throws on 401', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Unauthorized', { status: 401 })
    );
    await expect(
      api.discoverPassive({ iface: 'eth0', durationSeconds: 30, sources: ['ARP'] })
    ).rejects.toThrow();
  });

  // --- AC3 signal cases (RED: these fail until Task 1.1 adds the signal param) ---

  it('(signal-passthrough) passes AbortSignal to fetch init', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({ discovered: 1, deviceIds: [1], perSourceCount: { ARP: 1 }, sweepId: 9 }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );

    const controller = new AbortController();
    await api.discoverPassive(
      { iface: 'eth0', durationSeconds: 30, sources: ['ARP'] },
      controller.signal,
    );

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/discovery/passive');
    expect(init?.method).toBe('POST');
    // The signal must be forwarded to fetch — this FAILS until client.ts is updated
    expect((init as RequestInit & { signal?: AbortSignal }).signal).toBe(controller.signal);
    // Core contract still holds
    const body = JSON.parse(init?.body as string);
    expect(body).toEqual({ iface: 'eth0', durationSeconds: 30, sources: ['ARP'] });
    const headers = (init?.headers as Record<string, string>) ?? {};
    expect(headers['Authorization']).toBe('Bearer mock-token');
  });

  it('(no-signal back-compat) omitting signal still works and fetch receives signal===undefined', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({ discovered: 0, deviceIds: [], perSourceCount: {}, sweepId: 10 }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );

    await api.discoverPassive({ iface: '', durationSeconds: 30, sources: ['ARP', 'MDNS', 'PCAP'] });

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/discovery/passive');
    expect(init?.method).toBe('POST');
    // When no signal is passed the init must not carry one (undefined or absent)
    const signal = (init as RequestInit & { signal?: AbortSignal }).signal;
    expect(signal == null).toBe(true);
  });

  it('(abort-not-retried) AbortError rejects and fetch is called exactly once', async () => {
    const abortError = Object.assign(new Error('aborted'), { name: 'AbortError' });
    const mockFetch = vi.spyOn(global, 'fetch').mockRejectedValueOnce(abortError);

    const controller = new AbortController();
    await expect(
      api.discoverPassive(
        { iface: 'eth0', durationSeconds: 30, sources: ['ARP'] },
        controller.signal,
      )
    ).rejects.toMatchObject({ name: 'AbortError' });

    // The retry wrapper must NOT re-issue on an AbortError — fetch called exactly once
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});
