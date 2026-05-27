/**
 * URL-builder tests for {@link api.listFleetCves}. These pin the wire contract
 * for the new v3-F1 {@code kevOnly} and {@code sort} query params: present when
 * explicitly requested, absent when omitted. The backend's {@code Boolean
 * kevOnly} is permissive (defaults to false), so we explicitly omit the param
 * on the {@code undefined} case to keep the URL footprint minimal.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { api } from './client';

describe('api.listFleetCves URL building', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({ content: [], totalElements: 0, totalPages: 0, number: 0, size: 25 }),
      } as unknown as Response)),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function capturedUrl(): string {
    const fetchMock = globalThis.fetch as ReturnType<typeof vi.fn>;
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const firstArg = fetchMock.mock.calls[0][0];
    return typeof firstArg === 'string' ? firstArg : (firstArg as URL).toString();
  }

  it('listFleetCves_buildsKevOnlyParam_whenTrue', async () => {
    await api.listFleetCves(0, 25, undefined, undefined, true);
    expect(capturedUrl()).toContain('kevOnly=true');
  });

  it('listFleetCves_omitsKevOnlyParam_whenUndefined', async () => {
    await api.listFleetCves(0, 25);
    expect(capturedUrl()).not.toContain('kevOnly');
  });

  it('listFleetCves_buildsSortParam_whenCompositeRequested', async () => {
    await api.listFleetCves(0, 25, undefined, undefined, undefined, 'composite');
    expect(capturedUrl()).toContain('sort=composite');
  });

  it('listFleetCves_buildsSortParam_whenKevRequested', async () => {
    await api.listFleetCves(0, 25, undefined, undefined, undefined, 'kev');
    expect(capturedUrl()).toContain('sort=kev');
  });

  it('listFleetCves_buildsSortParam_whenEpssRequested', async () => {
    await api.listFleetCves(0, 25, undefined, undefined, undefined, 'epss');
    expect(capturedUrl()).toContain('sort=epss');
  });
});
