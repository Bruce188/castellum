import { Fragment, useCallback, useState } from 'react';
import { api } from '../api/client';
import type { CveDetailDto } from '../api/types';

interface Props {
  cveIds: string[];
  /** Optional set of CVE IDs known to be KEV-flagged. Caller may supply or omit. */
  kevIds?: Set<string>;
}

type DetailState = { status: 'idle' } | { status: 'loading' } | { status: 'ok'; detail: CveDetailDto } | { status: 'error'; message: string };

type SortKey = 'cveId' | 'cvss' | 'published';
type SortDir = 'asc' | 'desc';

/**
 * Renders a per-CVE evidence table for a device. Each row shows the CVE ID + KEV chip.
 * Clicking a row expands it and lazy-fetches GET /api/cve/{cveId}; the result is cached
 * in component state so a second click of the same row reuses the cached payload.
 *
 * <p>Sort controls toggle ordering across {cveId, cvss, published}. CVSS / published
 * sorting can only use values for rows whose detail has been fetched — undefined values
 * sink to the bottom.
 */
export function CveEvidenceTable({ cveIds, kevIds }: Props) {
  const [details, setDetails] = useState<Map<string, DetailState>>(new Map());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [sortKey, setSortKey] = useState<SortKey>('cveId');
  const [sortDir, setSortDir] = useState<SortDir>('asc');

  const ensureFetched = useCallback(async (cveId: string) => {
    setDetails(prev => {
      if (prev.has(cveId)) return prev;
      const next = new Map(prev);
      next.set(cveId, { status: 'loading' });
      return next;
    });
    // Skip the network call if we already have an ok/error result.
    const current = details.get(cveId);
    if (current && current.status !== 'loading' && current.status !== 'idle') return;
    try {
      const detail = await api.cveDetail(cveId);
      setDetails(prev => {
        const next = new Map(prev);
        next.set(cveId, { status: 'ok', detail });
        return next;
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to load CVE detail';
      setDetails(prev => {
        const next = new Map(prev);
        next.set(cveId, { status: 'error', message });
        return next;
      });
    }
  }, [details]);

  function toggle(cveId: string) {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(cveId)) {
        next.delete(cveId);
      } else {
        next.add(cveId);
        // Only fetch on the first expand; cached entries skip the call.
        const existing = details.get(cveId);
        if (!existing || existing.status === 'idle' || existing.status === 'error') {
          void ensureFetched(cveId);
        }
      }
      return next;
    });
  }

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir(d => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
  }

  function getCvss(cveId: string): number | null {
    const s = details.get(cveId);
    if (!s || s.status !== 'ok') return null;
    const raw = s.detail.cvssV31Score ?? s.detail.cvssV30Score ?? s.detail.cvssV2Score;
    if (raw === null || raw === undefined) return null;
    const n = Number(raw);
    return Number.isFinite(n) ? n : null;
  }

  function getPublished(cveId: string): number | null {
    const s = details.get(cveId);
    if (!s || s.status !== 'ok' || !s.detail.published) return null;
    const t = Date.parse(s.detail.published);
    return Number.isFinite(t) ? t : null;
  }

  const sortedIds = [...cveIds].sort((a, b) => {
    const factor = sortDir === 'asc' ? 1 : -1;
    if (sortKey === 'cveId') return a.localeCompare(b) * factor;
    if (sortKey === 'cvss') {
      const av = getCvss(a);
      const bv = getCvss(b);
      // null sinks to the bottom regardless of direction
      if (av === null && bv === null) return 0;
      if (av === null) return 1;
      if (bv === null) return -1;
      return (av - bv) * factor;
    }
    // published
    const ap = getPublished(a);
    const bp = getPublished(b);
    if (ap === null && bp === null) return 0;
    if (ap === null) return 1;
    if (bp === null) return -1;
    return (ap - bp) * factor;
  });

  if (cveIds.length === 0) {
    return <p className="text-sm text-gray-500">No matched CVEs.</p>;
  }

  return (
    <div data-testid="cve-evidence-table">
      <table className="w-full text-sm border-collapse">
        <thead>
          <tr className="text-left text-gray-500 border-b">
            <th className="py-1 pr-2">
              <button type="button" className="hover:underline" onClick={() => toggleSort('cveId')}>
                CVE {sortKey === 'cveId' && (sortDir === 'asc' ? '▲' : '▼')}
              </button>
            </th>
            <th className="py-1 pr-2">
              <button type="button" className="hover:underline" onClick={() => toggleSort('cvss')}>
                CVSS {sortKey === 'cvss' && (sortDir === 'asc' ? '▲' : '▼')}
              </button>
            </th>
            <th className="py-1 pr-2">EPSS</th>
            <th className="py-1 pr-2" data-testid="kev-col">KEV</th>
            <th className="py-1 pr-2">
              <button type="button" className="hover:underline" onClick={() => toggleSort('published')}>
                Published {sortKey === 'published' && (sortDir === 'asc' ? '▲' : '▼')}
              </button>
            </th>
          </tr>
        </thead>
        <tbody>
          {sortedIds.map(cveId => {
            const isOpen = expanded.has(cveId);
            const state = details.get(cveId);
            const cvss = state?.status === 'ok'
              ? (state.detail.cvssV31Score ?? state.detail.cvssV30Score ?? state.detail.cvssV2Score)
              : null;
            const isKev = kevIds?.has(cveId) ?? false;
            const publishedStr = state?.status === 'ok' && state.detail.published
              ? state.detail.published.slice(0, 10)
              : null;
            return (
              <Fragment key={cveId}>
                <tr
                  className="border-b hover:bg-gray-50 cursor-pointer"
                  onClick={() => toggle(cveId)}
                >
                  <td className="py-1 pr-2 font-mono">{cveId}</td>
                  <td className="py-1 pr-2">{cvss ?? '—'}</td>
                  <td className="py-1 pr-2 text-gray-500">—</td>
                  <td className="py-1 pr-2" data-testid="kev-cell">
                    {isKev ? (
                      <span className="inline-block px-1 rounded bg-red-100 text-red-800 text-xs">KEV</span>
                    ) : (
                      <span className="text-gray-400">—</span>
                    )}
                  </td>
                  <td className="py-1 pr-2 text-gray-500">{publishedStr ?? '—'}</td>
                </tr>
                {isOpen && (
                  <tr className="bg-gray-50">
                    <td colSpan={5} className="p-2 text-xs">
                      {!state || state.status === 'idle' || state.status === 'loading' ? (
                        <span className="text-gray-400">Loading {cveId}…</span>
                      ) : state.status === 'error' ? (
                        <span className="text-red-600">{state.message}</span>
                      ) : (
                        <div className="space-y-1">
                          {state.detail.description && (
                            <p className="whitespace-pre-wrap">{state.detail.description}</p>
                          )}
                          <dl className="grid grid-cols-[max-content_1fr] gap-x-2 text-gray-600">
                            <dt>status</dt><dd>{state.detail.vulnStatus ?? '—'}</dd>
                            <dt>last modified</dt><dd>{state.detail.lastModified}</dd>
                            {state.detail.cvssV31Vector && (
                              <>
                                <dt>vector</dt><dd className="font-mono break-all">{state.detail.cvssV31Vector}</dd>
                              </>
                            )}
                          </dl>
                        </div>
                      )}
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
