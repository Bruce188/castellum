import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.getIntegrationConfig()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('GETs /api/integrations/TAXII and returns the config DTO', async () => {
    const payload = {
      id: 1,
      integrationType: 'TAXII',
      config: { url: 'https://taxii.example' },
      credentialsSet: true,
      lastPushAt: null,
      lastPushStatus: null,
      createdAt: '2026-05-26T00:00:00Z',
      updatedAt: '2026-05-26T00:00:00Z',
    };
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(payload), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const cfg = await api.getIntegrationConfig('TAXII');
    expect(cfg.integrationType).toBe('TAXII');
    expect(cfg.credentialsSet).toBe(true);

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/integrations/TAXII');
    // request() does not set an explicit method — fetch defaults to GET.
    expect(init?.method).toBeUndefined();
  });

  it('GETs MISP type via the same endpoint family', async () => {
    const payload = {
      id: 2,
      integrationType: 'MISP',
      config: { url: 'https://misp.example' },
      credentialsSet: false,
      lastPushAt: null,
      lastPushStatus: null,
      createdAt: '2026-05-26T00:00:00Z',
      updatedAt: '2026-05-26T00:00:00Z',
    };
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(payload), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const cfg = await api.getIntegrationConfig('MISP');
    expect(cfg.integrationType).toBe('MISP');
    expect(cfg.credentialsSet).toBe(false);

    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/integrations/MISP');
  });

  it('throws 404 error when config is missing', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Not Found', { status: 404 })
    );
    await expect(api.getIntegrationConfig('TAXII')).rejects.toThrow(/404/);
  });
});
