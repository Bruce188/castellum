import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('api.saveIntegrationConfig()', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('PUTs config+credentials to /api/integrations/{type}', async () => {
    const responseBody = {
      id: 5,
      integrationType: 'TAXII',
      config: { url: 'https://taxii.example', collectionId: 'cid' },
      credentialsSet: true,
      lastPushAt: null,
      lastPushStatus: null,
      createdAt: '2026-05-26T00:00:00Z',
      updatedAt: '2026-05-26T00:00:00Z',
    };
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(responseBody), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const result = await api.saveIntegrationConfig('TAXII', {
      config: { url: 'https://taxii.example', collectionId: 'cid' },
      credentials: 'super-secret',
    });
    expect(result.integrationType).toBe('TAXII');

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/integrations/TAXII');
    expect(init?.method).toBe('PUT');
    const body = JSON.parse(init?.body as string);
    expect(body.config.url).toBe('https://taxii.example');
    expect(body.config.collectionId).toBe('cid');
    expect(body.credentials).toBe('super-secret');
  });

  it('PUTs MISP config with a single api-key credential', async () => {
    const responseBody = {
      id: 8,
      integrationType: 'MISP',
      config: { url: 'https://misp.example' },
      credentialsSet: true,
      lastPushAt: null,
      lastPushStatus: null,
      createdAt: '2026-05-26T00:00:00Z',
      updatedAt: '2026-05-26T00:00:00Z',
    };
    const mockFetch = vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(responseBody), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    await api.saveIntegrationConfig('MISP', {
      config: { url: 'https://misp.example' },
      credentials: 'misp-api-key-XYZ',
    });

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/api/integrations/MISP');
    const body = JSON.parse(init?.body as string);
    expect(body.credentials).toBe('misp-api-key-XYZ');
  });

  it('throws on non-2xx', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(
      new Response('Bad Request', { status: 400 })
    );
    await expect(
      api.saveIntegrationConfig('TAXII', { config: {}, credentials: '' })
    ).rejects.toThrow(/400/);
  });
});
