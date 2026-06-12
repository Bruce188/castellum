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
    const controller = new AbortController();
    // The client owns the signal handed to fetch (so it can abort a wedged
    // error-body read) and COMPOSES the caller's signal into it: the caller's
    // abort intent must reach the fetch WHILE the request is in flight. The
    // relay is detached once the request settles, so the check has to happen
    // inside the mocked fetch, not after the call returns.
    let forwardedAbortedBefore: boolean | undefined;
    let forwardedAbortedAfterCallerAbort: boolean | undefined;
    const mockFetch = vi.spyOn(global, 'fetch').mockImplementationOnce(async (_url, init) => {
      const forwarded = (init as RequestInit & { signal?: AbortSignal }).signal;
      expect(forwarded).toBeInstanceOf(AbortSignal);
      forwardedAbortedBefore = forwarded?.aborted;
      controller.abort();
      forwardedAbortedAfterCallerAbort = forwarded?.aborted;
      return new Response(
        JSON.stringify({ discovered: 1, deviceIds: [1], perSourceCount: { ARP: 1 }, sweepId: 9 }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      );
    });

    await api.discoverPassive(
      { iface: 'eth0', durationSeconds: 30, sources: ['ARP'] },
      controller.signal,
    );

    expect(forwardedAbortedBefore).toBe(false);
    expect(forwardedAbortedAfterCallerAbort).toBe(true);
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/discovery/passive');
    expect(init?.method).toBe('POST');
    // Core contract still holds
    const body = JSON.parse(init?.body as string);
    expect(body).toEqual({ iface: 'eth0', durationSeconds: 30, sources: ['ARP'] });
    const headers = (init?.headers as Record<string, string>) ?? {};
    expect(headers['Authorization']).toBe('Bearer mock-token');
  });

  it('(no-signal back-compat) omitting signal still works and the forwarded signal never aborts spuriously', async () => {
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
    // The client always passes its own owned signal (used to release a wedged
    // error-body stream); with no caller signal composed in, it must be live.
    const signal = (init as RequestInit & { signal?: AbortSignal }).signal;
    expect(signal).toBeInstanceOf(AbortSignal);
    expect(signal?.aborted).toBe(false);
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
