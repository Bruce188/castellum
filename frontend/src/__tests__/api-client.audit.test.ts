import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../hooks/useAuth', () => ({
  getToken: () => 'mock-token',
  clearAuth: vi.fn(),
}));

import { api } from '../api/client';

describe('audit client', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    // Ensure localStorage has a token for downloadAuditCsv
    globalThis.localStorage.setItem('castellum.jwt', 'fake-jwt');
  });

  it('listAudit builds query string from filters', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        '{"content":[],"totalElements":0,"totalPages":0,"number":0,"size":50}',
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );
    await api.listAudit({ since: '2026-05-01T00:00:00Z', action: 'SCAN_SUBMIT', size: 25 });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const url = String(fetchSpy.mock.calls[0][0]);
    expect(url).toContain('since=2026-05-01T00%3A00%3A00Z');
    expect(url).toContain('action=SCAN_SUBMIT');
    expect(url).toContain('size=25');
    expect(url).toContain('sort=occurredAt%2Cdesc');
  });

  it('listAudit skips empty filters', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        '{"content":[],"totalElements":0,"totalPages":0,"number":0,"size":50}',
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );
    await api.listAudit({ action: '', actor: undefined });
    const url = String(fetchSpy.mock.calls[0][0]);
    expect(url).not.toContain('action=');
    expect(url).not.toContain('actor=');
  });

  it('downloadAuditCsv returns blob on 200', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('csv body', { status: 200, headers: { 'content-type': 'text/csv' } })
    );
    const blob = await api.downloadAuditCsv({});
    // Blob from fetch Response.blob() in jsdom — check shape rather than instanceof
    expect(blob.size).toBeGreaterThan(0);
    expect(typeof blob.type).toBe('string');
  });

  it('downloadAuditCsv throws with count on 413', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        '{"error":"csv_cap_exceeded","limit":10000,"filteredCount":12345}',
        { status: 413, headers: { 'content-type': 'application/json' } }
      )
    );
    await expect(api.downloadAuditCsv({})).rejects.toThrow(/12345/);
  });
});
