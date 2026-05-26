import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

/**
 * Covers the bounded-retry wrapper around the shared {@code request()} helper.
 *
 * The wrapper retries exactly once on:
 *   - {@link TypeError} (browser network failure)
 *   - HTTP 502 / 503 / 504
 *
 * No retry on 4xx — those are caller errors and surfacing them immediately
 * matches the pre-existing UX (Failed-to-fetch pill).
 */
describe('request() retry wrapper', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('retries once on HTTP 503 and surfaces the second-try success', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
      .mockResolvedValueOnce(new Response('boom', { status: 503, statusText: 'Service Unavailable' }))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ deviceId: 7, score: '6.25', topCveIds: [] }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
      );

    const out = await api.deviceRisk(7);

    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(out.deviceId).toBe(7);
    expect(out.score).toBe('6.25');
  });

  it('retries once on HTTP 502 and surfaces the second-try success', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
      .mockResolvedValueOnce(new Response('boom', { status: 502, statusText: 'Bad Gateway' }))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ epss: { scoreDate: null, rowCount: 0 }, kev: { lastIngestedAt: null, entryCount: 0 }, nvd: { lastModified: null, rowCount: 0 } }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
      );

    await api.feedsStatus();
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it('retries once on HTTP 504 and surfaces the second-try success', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
      .mockResolvedValueOnce(new Response('boom', { status: 504, statusText: 'Gateway Timeout' }))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ content: [], totalElements: 0, totalPages: 0, number: 0, size: 200 }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
      );

    await api.listDevices();
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it('retries once on TypeError (network failure) and surfaces the second-try success', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
      .mockRejectedValueOnce(new TypeError('Failed to fetch'))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ deviceId: 1, score: '0.00', topCveIds: [] }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
      );

    const out = await api.deviceRisk(1);
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(out.deviceId).toBe(1);
  });

  it('does NOT retry on HTTP 400 — surfaces the error immediately', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
      .mockResolvedValueOnce(new Response('bad', { status: 400, statusText: 'Bad Request' }));

    await expect(api.deviceRisk(1)).rejects.toThrow('400');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('does NOT retry on HTTP 403 — preserves the listInterfaces 403→[] semantic', async () => {
    // listInterfaces() catches its own 403 and returns []. The retry wrapper
    // must not double-fire the request before that catch can fold the failure.
    const fetchSpy = vi.spyOn(global, 'fetch')
      .mockResolvedValueOnce(new Response('Forbidden', { status: 403 }));

    await expect(api.listInterfaces()).resolves.toEqual([]);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('does NOT retry on HTTP 404 — surfaces the error immediately', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
      .mockResolvedValueOnce(new Response('Not Found', { status: 404, statusText: 'Not Found' }));

    await expect(api.deviceRisk(99)).rejects.toThrow('404');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('does NOT retry on HTTP 500 — only 502/503/504 are retried', async () => {
    // 500 is a genuine app error, not a transient gateway/upstream failure.
    // Retrying could mask real bugs — keep the existing surface behavior.
    const fetchSpy = vi.spyOn(global, 'fetch')
      .mockResolvedValueOnce(new Response('boom', { status: 500, statusText: 'Internal Server Error' }));

    await expect(api.deviceRisk(1)).rejects.toThrow('500');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('surfaces the final error if BOTH attempts fail with a retryable status', async () => {
    // Two consecutive 503s — the wrapper retries once, then the second failure
    // propagates as the canonical "503 Service Unavailable" message.
    const fetchSpy = vi.spyOn(global, 'fetch')
      .mockResolvedValueOnce(new Response('boom', { status: 503, statusText: 'Service Unavailable' }))
      .mockResolvedValueOnce(new Response('boom', { status: 503, statusText: 'Service Unavailable' }));

    await expect(api.deviceRisk(1)).rejects.toThrow('503');
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it('401 still clears auth on first attempt and does not retry', async () => {
    // 401 is short-circuited inside requestOnce — it throws a custom message
    // AND clears auth. The wrapper must not retry because that would clear
    // auth a second time + double-call the endpoint.
    const fetchSpy = vi.spyOn(global, 'fetch')
      .mockResolvedValueOnce(new Response('nope', { status: 401, statusText: 'Unauthorized' }));

    await expect(api.deviceRisk(1)).rejects.toThrow('401 Unauthorized');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});
