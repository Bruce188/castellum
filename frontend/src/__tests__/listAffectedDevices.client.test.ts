import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { api } from '../api/client';

// RED: api.listAffectedDevices does not yet exist — this file will fail at the
// TypeScript compile step (tsc) / vitest import phase until Task 3 GREEN.
describe('api.listAffectedDevices', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('calls GET /api/cve/{cveId}/devices and returns the list', async () => {
    const mockFetch = vi.mocked(fetch);
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => [
        { deviceId: 42, hostname: 'host-1', ipAddress: '10.0.0.42',
          matchedPort: 22, matchedService: 'openssh', matchedVersion: '8.2' },
      ],
    } as Response);

    const result = await api.listAffectedDevices('CVE-2020-15778');

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/cve/CVE-2020-15778/devices'),
      expect.any(Object),
    );
    expect(result).toHaveLength(1);
    expect(result[0].deviceId).toBe(42);
    expect(result[0].matchedService).toBe('openssh');
  });

  it('returns empty array when no devices are affected', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => [],
    } as Response);

    const result = await api.listAffectedDevices('CVE-2020-15778');
    expect(result).toHaveLength(0);
  });
});
