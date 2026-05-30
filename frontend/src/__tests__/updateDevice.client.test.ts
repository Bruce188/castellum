import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';
import type { Device } from '../api/types';

const current: Device = {
  id: 5,
  ipAddress: '10.0.0.5',
  hostname: 'old-host',
  macAddress: null,
  firstSeen: null,
  lastSeen: null,
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

describe('api.updateDevice()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('PUTs /api/devices/{id} with Authorization header', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({ ...current, criticality: 'CRITICAL' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    await api.updateDevice(5, current, { criticality: 'CRITICAL' });

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/devices/5');
    expect(init?.method).toBe('PUT');
    expect((init?.headers as Record<string, string>)?.['Authorization']).toBe('Bearer mock-token');
  });

  it('merges patch over current device fields (criticality only)', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({ ...current, criticality: 'HIGH' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    await api.updateDevice(5, current, { criticality: 'HIGH' });

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init?.body as string);
    // Preserved fields
    expect(body.ipAddress).toBe('10.0.0.5');
    expect(body.hostname).toBe('old-host');
    // Patched field
    expect(body.criticality).toBe('HIGH');
  });

  it('hostname patch (including null) is honored', async () => {
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({ ...current, hostname: 'renamed' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    await api.updateDevice(5, current, { hostname: 'renamed' });
    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init?.body as string);
    expect(body.hostname).toBe('renamed');
    expect(body.criticality).toBe('MEDIUM'); // preserved from current
  });

  it('throws on 403 (VIEWER attempt)', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Forbidden', { status: 403, headers: { 'content-type': 'application/json' } })
    );
    await expect(api.updateDevice(5, current, { criticality: 'LOW' })).rejects.toThrow('403');
  });

  it('throws on 401 (token expired)', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Unauthorized', { status: 401, headers: { 'content-type': 'application/json' } })
    );
    await expect(api.updateDevice(5, current, { criticality: 'LOW' })).rejects.toThrow();
  });
});
