import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { CveDetailPanel } from '../components/CveDetailPanel';
import type { CveFleetSort, CveSummaryDto, Page } from '../api/types';

const PAGE_SIZE = 25;

type SeverityFilter = 'all' | 'high' | 'critical';

const SEVERITY_THRESHOLDS: Record<Exclude<SeverityFilter, 'all'>, number> = {
  high: 7.0,
  critical: 9.0,
};

/**
 * Color ramp for a numeric severity / composite score. Bands match the
 * conventional CVSS-style buckets: critical (≥9), high (≥7), medium (≥4),
 * low (<4); the null branch returns a muted grey so the cell still reads as
 * "no signal" rather than as a true 0.0 score.
 */
function severityClass(score: number | null): string {
  if (score === null) return 'text-gray-500';
  if (score >= 9.0) return 'text-red-700 font-semibold';
  if (score >= 7.0) return 'text-orange-600 font-medium';
  if (score >= 4.0) return 'text-amber-600';
  return 'text-gray-600';
}

/** {@link severityClass} but pre-parses the BigDecimal-as-string wire value. */
function severityClassFromString(score: string | null): string {
  return severityClass(score === null ? null : Number(score));
}

function isSeverity(s: string): s is SeverityFilter {
  return s === 'all' || s === 'high' || s === 'critical';
}

function isSort(s: string): s is CveFleetSort {
  return s === 'composite' || s === 'cvss' || s === 'kev' || s === 'epss';
}

export function CvesPage() {
  const [searchParams, setSearchParams] = useSearchParams();

  // v3-F1 — migrate severity + page + kevOnly + sort to URL state for deep-link
  // sharing (analysis Decision 6). deviceId is already URL-bound from v6-F1.
  const rawId = searchParams.get('deviceId');
  const parsedId = rawId !== null ? Number(rawId) : NaN;
  const deviceId = Number.isFinite(parsedId) ? parsedId : null;

  const severityParam = searchParams.get('severity') ?? 'all';
  const severity: SeverityFilter = isSeverity(severityParam) ? severityParam : 'all';
  const pageNumber = Math.max(0, Number(searchParams.get('page') ?? '0') | 0);
  const kevOnly = searchParams.get('kevOnly') === 'true';
  const sortParam = searchParams.get('sort');
  // Default to 'composite' so a no-param load (a fresh /cves visit or a shared
  // link without ?sort=) requests composite-DESC. Clicking any column header
  // writes an explicit ?sort=<key> via onSortToggle, so the active ordering is
  // always reflected in the URL. An explicit ?sort= always wins (parsed first).
  const sort: CveFleetSort =
    sortParam !== null && isSort(sortParam) ? sortParam : 'composite';

  const rawQ = searchParams.get('q') ?? '';
  const searchQuery = rawQ;

  const [page, setPage] = useState<Page<CveSummaryDto> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deviceLabel, setDeviceLabel] = useState<string | null>(null);
  // F8 — CVE selected for the detail drawer (null = drawer closed).
  const [selectedCveId, setSelectedCveId] = useState<string | null>(null);

  // Manual refresh path (Refresh button). Ref-based request-id versioning
  // discards results from any superseded in-flight invocation when the user
  // clicks Refresh faster than the network resolves.
  const requestIdRef = useRef(0);
  const fetchPage = useCallback(async () => {
    const myRequestId = ++requestIdRef.current;
    setLoading(true);
    setError(null);
    try {
      const minScore = severity === 'all' ? undefined : SEVERITY_THRESHOLDS[severity];
      const result = await api.listFleetCves(
        pageNumber,
        PAGE_SIZE,
        minScore,
        deviceId ?? undefined,
        kevOnly || undefined,
        sort,
      );
      if (myRequestId !== requestIdRef.current) return;
      setPage(result);
    } catch (err) {
      if (myRequestId !== requestIdRef.current) return;
      setError(err instanceof Error ? err.message : 'Failed to load CVEs');
      setPage(null);
    } finally {
      if (myRequestId === requestIdRef.current) setLoading(false);
    }
  }, [pageNumber, severity, deviceId, kevOnly, sort]);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      if (cancelled) return;
      setLoading(true);
      setError(null);
      try {
        const minScore = severity === 'all' ? undefined : SEVERITY_THRESHOLDS[severity];
        const result = await api.listFleetCves(
          pageNumber,
          PAGE_SIZE,
          minScore,
          deviceId ?? undefined,
          kevOnly || undefined,
          sort,
        );
        if (cancelled) return;
        setPage(result);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Failed to load CVEs');
        setPage(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void run();
    return () => { cancelled = true; };
  }, [pageNumber, severity, deviceId, kevOnly, sort]);

  useEffect(() => {
    if (deviceId === null) return;
    let cancelled = false;
    (async () => {
      try {
        const dev = await api.getDevice(deviceId);
        if (cancelled) return;
        setDeviceLabel(`${dev.hostname ?? 'unknown'} (${dev.ipAddress})`);
      } catch {
        if (cancelled) return;
        setDeviceLabel(null);
      }
    })();
    return () => {
      cancelled = true;
      // Reset label on cleanup so a subsequent deviceId param shows the bare-id
      // fallback until the fresh lookup resolves.
      setDeviceLabel(null);
    };
  }, [deviceId]);

  const onSeverityChange = (next: SeverityFilter) => {
    setSearchParams(prev => {
      const params = new URLSearchParams(prev);
      if (next === 'all') params.delete('severity');
      else params.set('severity', next);
      params.delete('page');
      return params;
    });
  };

  /**
   * Set sort to the clicked column. A header click always writes an explicit
   * {@code ?sort=<key>} — including for the composite default — so the active
   * ordering is deep-linkable/shareable and a column-header click is always
   * observable in the URL (conventional table-sort UX). Always resets
   * {@code page} back to 0 because changing the order key under a stale page
   * index would surface a confusing slice of the new ordering (e.g. lingering
   * on page 4 of CVSS-DESC while sorting flipped to composite-DESC). Matches
   * the page-reset convention of severity and KEV toggles. (code-reviewer NB-2)
   */
  const onSortToggle = (key: CveFleetSort) => {
    setSearchParams(prev => {
      const params = new URLSearchParams(prev);
      params.set('sort', key);
      params.delete('page');
      return params;
    });
  };

  const onKevOnlyToggle = () => {
    setSearchParams(prev => {
      const params = new URLSearchParams(prev);
      if (kevOnly) params.delete('kevOnly');
      else params.set('kevOnly', 'true');
      params.delete('page');
      return params;
    });
  };

  const onSearchChange = (next: string) => {
    setSearchParams(prev => {
      const params = new URLSearchParams(prev);
      if (next === '') params.delete('q');
      else params.set('q', next);
      params.delete('page');
      return params;
    });
  };

  const setPageNumber = (next: number) => {
    setSearchParams(prev => {
      const params = new URLSearchParams(prev);
      if (next === 0) params.delete('page');
      else params.set('page', String(next));
      return params;
    });
  };

  // visibleRows: filter page.content by cveId substring (client-side search),
  // then apply composite stable tiebreak when sort is 'composite' (incl. default).
  // For non-composite sorts the server order is preserved.
  const visibleRows = useMemo<CveSummaryDto[]>(() => {
    const content = page?.content ?? [];

    // Filter first (case-insensitive cveId substring)
    const filtered = searchQuery
      ? content.filter(cve =>
          cve.cveId.toLowerCase().includes(searchQuery.toLowerCase()),
        )
      : content;

    if (sort !== 'composite') return filtered;

    // Stable composite tiebreak: compositeScore DESC → kev DESC → epssScore DESC → cveId ASC
    return [...filtered].sort((a, b) => {
      const aComposite = a.compositeScore !== null ? Number(a.compositeScore) : -Infinity;
      const bComposite = b.compositeScore !== null ? Number(b.compositeScore) : -Infinity;
      if (bComposite !== aComposite) return bComposite - aComposite;

      // kev true first (DESC)
      if (a.kev !== b.kev) return a.kev ? -1 : 1;

      const aEpss = a.epssScore !== null ? Number(a.epssScore) : -Infinity;
      const bEpss = b.epssScore !== null ? Number(b.epssScore) : -Infinity;
      if (bEpss !== aEpss) return bEpss - aEpss;

      // cveId ASC
      return a.cveId < b.cveId ? -1 : a.cveId > b.cveId ? 1 : 0;
    });
  }, [page, sort, searchQuery]);

  return (
    <div className="h-full overflow-auto p-6">
      <div className="flex items-baseline justify-between mb-4">
        <h1 className="text-xl font-semibold text-gray-800">CVEs</h1>
        <div className="text-sm text-gray-500">
          {page
            ? `${page.totalElements} CVEs, page ${page.number + 1}/${Math.max(page.totalPages, 1)}`
            : loading
              ? 'Loading…'
              : ''}
        </div>
      </div>

      {deviceId !== null && (
        <div className="inline-flex items-center gap-2 mb-3 px-2 py-1 text-sm bg-blue-50 border border-blue-200 rounded">
          <span>Device filter: {deviceLabel ?? `device #${deviceId}`}</span>
          <button
            type="button"
            data-testid="cves-chip-dismiss"
            aria-label="Clear device filter"
            onClick={() => setSearchParams({})}
            className="text-blue-700 hover:text-blue-900"
          >
            ×
          </button>
        </div>
      )}

      <div className="flex items-center gap-2 mb-3">
        <label className="text-sm text-gray-700">Severity floor:</label>
        <select
          value={severity}
          onChange={(e) => onSeverityChange(e.target.value as SeverityFilter)}
          className="text-sm border rounded px-2 py-1"
        >
          <option value="all">All scored</option>
          <option value="high">High (≥ 7.0)</option>
          <option value="critical">Critical (≥ 9.0)</option>
        </select>
        <button
          type="button"
          data-testid="kev-only-toggle"
          aria-pressed={kevOnly}
          onClick={onKevOnlyToggle}
          className={
            kevOnly
              ? 'text-sm bg-red-100 text-red-700 rounded px-2 py-1 border border-red-300'
              : 'text-sm border rounded px-2 py-1 hover:bg-gray-50'
          }
        >
          KEV only
        </button>
        <input
          type="search"
          data-testid="cves-search-input"
          aria-label="Search CVE id"
          placeholder="Search CVE id…"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          className="text-sm border rounded px-2 py-1 w-40"
        />
        <button
          type="button"
          onClick={fetchPage}
          className="text-sm border rounded px-2 py-1 hover:bg-gray-50"
        >
          Refresh
        </button>
      </div>

      {error && <div className="text-sm text-red-700 mb-2">{error}</div>}

      <table className="w-full text-sm border-collapse">
        <thead>
          <tr className="bg-gray-100 text-left">
            <th className="px-2 py-1 border">CVE ID</th>
            <th
              className="px-2 py-1 border w-20"
              aria-sort={sort === 'cvss' ? 'descending' : 'none'}
            >
              <button
                type="button"
                onClick={() => onSortToggle('cvss')}
                className="font-semibold hover:underline"
              >
                CVSS v3.1{sort === 'cvss' ? ' ↓' : ' ↕'}
              </button>
            </th>
            <th
              className="px-2 py-1 border w-16"
              aria-sort={sort === 'kev' ? 'descending' : 'none'}
            >
              <button
                type="button"
                onClick={() => onSortToggle('kev')}
                className="font-semibold hover:underline"
              >
                KEV{sort === 'kev' ? ' ↓' : ' ↕'}
              </button>
            </th>
            <th
              className="px-2 py-1 border w-20"
              aria-sort={sort === 'epss' ? 'descending' : 'none'}
            >
              <button
                type="button"
                onClick={() => onSortToggle('epss')}
                className="font-semibold hover:underline"
              >
                EPSS{sort === 'epss' ? ' ↓' : ' ↕'}
              </button>
            </th>
            <th
              className="px-2 py-1 border w-24"
              aria-sort={sort === 'composite' ? 'descending' : 'none'}
            >
              <button
                type="button"
                onClick={() => onSortToggle('composite')}
                className="font-semibold hover:underline"
              >
                Composite{sort === 'composite' ? ' ↓' : ' ↕'}
              </button>
            </th>
            <th className="px-2 py-1 border">Description</th>
            <th className="px-2 py-1 border w-32">Last Modified</th>
          </tr>
        </thead>
        <tbody>
          {visibleRows.map((cve) => (
            <tr
              key={cve.cveId}
              className="border-b hover:bg-gray-50 select-none cursor-pointer"
              onClick={() => setSelectedCveId(cve.cveId)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => e.key === 'Enter' && setSelectedCveId(cve.cveId)}
              aria-label={`View details for ${cve.cveId}`}
            >
              <td className="px-2 py-1 border font-mono text-xs select-text">{cve.cveId}</td>
              <td className={`px-2 py-1 border tabular-nums ${severityClassFromString(cve.cvssV31Score)}`}>
                {cve.cvssV31Score ?? '—'}
              </td>
              <td className="px-2 py-1 border select-text">
                {cve.kev ? (
                  <span
                    data-testid="kev-badge"
                    className="bg-red-100 text-red-700 rounded px-2 py-0.5 text-xs font-semibold"
                  >
                    KEV
                  </span>
                ) : (
                  <span className="text-gray-400">—</span>
                )}
              </td>
              <td className="px-2 py-1 border tabular-nums select-text">
                {cve.epssScore != null
                  ? `${(Number(cve.epssScore) * 100).toFixed(2)}%`
                  : <span className="text-gray-400">—</span>}
              </td>
              <td className={`px-2 py-1 border tabular-nums select-text ${severityClassFromString(cve.compositeScore)}`}>
                {cve.compositeScore != null
                  ? Number(cve.compositeScore).toFixed(2)
                  : <span className="text-gray-400">—</span>}
              </td>
              <td className="px-2 py-1 border text-gray-700 truncate max-w-xl select-text">
                {cve.description ?? <span className="text-gray-400">no description</span>}
              </td>
              <td className="px-2 py-1 border text-xs text-gray-600 tabular-nums">
                {cve.lastModified?.slice(0, 10)}
              </td>
            </tr>
          ))}
          {loading && (!page || page.content.length === 0) && (
            <tr>
              <td colSpan={7} className="px-2 py-6 text-center text-gray-500">
                <span className="inline-flex items-center gap-2">
                  <span
                    data-testid="cves-loading-spinner"
                    className="inline-block h-4 w-4 rounded-full border-2 border-gray-300 border-t-gray-600 animate-spin"
                  />
                  Loading CVEs…
                </span>
              </td>
            </tr>
          )}
          {!loading && page && visibleRows.length === 0 && (
            <tr>
              <td colSpan={7} className="px-2 py-4 text-center text-gray-500 italic">
                No CVEs match this filter.
              </td>
            </tr>
          )}
        </tbody>
      </table>

      {page && page.totalPages > 1 && (
        <div className="flex items-center gap-2 mt-3 text-sm">
          <button
            type="button"
            disabled={pageNumber === 0}
            onClick={() => setPageNumber(Math.max(pageNumber - 1, 0))}
            className="border rounded px-2 py-1 disabled:opacity-40"
          >
            Prev
          </button>
          <button
            type="button"
            disabled={pageNumber + 1 >= page.totalPages}
            onClick={() => setPageNumber(pageNumber + 1)}
            className="border rounded px-2 py-1 disabled:opacity-40"
          >
            Next
          </button>
          <span className="text-gray-600">
            Page {pageNumber + 1} of {page.totalPages}
          </span>
        </div>
      )}

      <CveDetailPanel
        cveId={selectedCveId}
        onClose={() => setSelectedCveId(null)}
      />
    </div>
  );
}
