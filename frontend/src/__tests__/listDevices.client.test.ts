import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';
import type { Device } from '../api/types';

/**
 * Covers the full-fleet pagination walk in {@link api.listDevices}: the
 * client now requests every page (deterministic {@code sort=id,asc}) and
 * returns one merged {@code Page<Device>} so device #201+ stops vanishing
 * from every consumer. A 25-page safety ceiling warns and returns the
 * partial fleet instead of looping forever.
 */
function makeDevice(id: number): Device {
  return {
    id,
    ipAddress: `10.${Math.floor(id / 65536) % 256}.${Math.floor(id / 256) % 256}.${id % 256}`,
    hostname: null,
    macAddress: null,
    firstSeen: '2026-01-01T00:00:00Z',
    lastSeen: '2026-01-01T00:00:00Z',
    criticality: 'MEDIUM',
    discoveryScope: 'HOME',
    lastSeenIface: null,
    discoverySource: null,
    serviceCount: 0,
    osName: null,
    osAccuracy: null,
    osCpe: null,
    publishesHostPort: false,
    deviceRole: 'UNKNOWN',
    originHostIp: 'local',
    originHostName: null,
    networkName: null,
  };
}

function pageResponse(ids: number[], totalElements: number, pageNumber: number): Response {
  return new Response(
    JSON.stringify({
      content: ids.map(makeDevice),
      totalElements,
      totalPages: Math.ceil(totalElements / 200),
      number: pageNumber,
      size: 200,
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

function range(start: number, count: number): number[] {
  return Array.from({ length: count }, (_, i) => start + i);
}

describe('api.listDevices() pagination walk', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('fetches a single page with size=200 and sort=id,asc when the fleet fits', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
      .mockResolvedValueOnce(pageResponse(range(1, 3), 3, 0));

    const out = await api.listDevices();

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/devices?size=200&sort=id,asc');
    expect(out.content).toHaveLength(3);
    expect(out.totalElements).toBe(3);
  });

  it('merges 450 devices across 3 pages and keeps the Page shape', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
      .mockResolvedValueOnce(pageResponse(range(1, 200), 450, 0))
      .mockResolvedValueOnce(pageResponse(range(201, 200), 450, 1))
      .mockResolvedValueOnce(pageResponse(range(401, 50), 450, 2));

    const out = await api.listDevices();

    expect(fetchSpy).toHaveBeenCalledTimes(3);
    const urls = fetchSpy.mock.calls.map(c => String(c[0]));
    expect(urls[1]).toContain('page=1');
    expect(urls[1]).toContain('sort=id,asc');
    expect(urls[2]).toContain('page=2');
    expect(out.content).toHaveLength(450);
    expect(out.totalElements).toBe(450);
    // Device #201 — previously silently dropped — is present in the merge.
    expect(out.content.some(d => d.id === 201)).toBe(true);
  });

  it('stops at the 25-page ceiling with a console.warn and returns the partial fleet', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      const page = Number(new URL(url).searchParams.get('page') ?? '0');
      return pageResponse(range(page * 200 + 1, 200), 6000, page);
    });
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const out = await api.listDevices();

    // Pages 0..24 — the ceiling caps the walk at 25 requests / 5000 devices.
    expect(fetchSpy).toHaveBeenCalledTimes(25);
    expect(out.content).toHaveLength(5000);
    expect(out.totalElements).toBe(6000);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(String(warnSpy.mock.calls[0][0])).toContain('5000 of 6000');
  });

  it('stops on an unexpected empty page instead of looping forever', async () => {
    // totalElements claims 400 but page 1 comes back empty (fleet shrank
    // mid-walk) — the defensive guard must bail with what we have.
    const fetchSpy = vi.spyOn(global, 'fetch')
      .mockResolvedValueOnce(pageResponse(range(1, 200), 400, 0))
      .mockResolvedValueOnce(pageResponse([], 400, 1));

    const out = await api.listDevices();

    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(out.content).toHaveLength(200);
  });
});
