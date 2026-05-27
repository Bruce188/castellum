import { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
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
  const sort: CveFleetSort | undefined =
    sortParam !== null && isSort(sortParam) ? sortParam : undefined;

  const [page, setPage] = useState<Page<CveSummaryDto> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deviceLabel, setDeviceLabel] = useState<string | null>(null);

  /** Single-key URL param update; null clears the key. Page is reset by callers. */
  const updateParam = useCallback(
    (key: string, value: string | null) => {
      setSearchParams(prev => {
        const next = new URLSearchParams(prev);
        if (value === null || value === '') next.delete(key);
        else next.set(key, value);
        return next;
      });
    },
    [setSearchParams],
  );

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
   * Toggle sort: clicking the active sort key clears it; otherwise sets to that
   * key. Always resets {@code page} back to 0 because changing the order
   * key under a stale page index would surface a confusing slice of the new
   * ordering (e.g. lingering on page 4 of CVSS-DESC while sorting flipped to
   * composite-DESC). Matches the page-reset convention of severity and KEV
   * toggles. (code-reviewer NB-2)
   */
  const onSortToggle = (key: CveFleetSort) => {
    setSearchParams(prev => {
      const params = new URLSearchParams(prev);
      if (sort === key) params.delete('sort');
      else params.set('sort', key);
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

  const setPageNumber = (next: number) => {
    setSearchParams(prev => {
      const params = new URLSearchParams(prev);
      if (next === 0) params.delete('page');
      else params.set('page', String(next));
      return params;
    });
  };

  return (
    <div className="h-full overflow-auto p-6">
      <div className="flex items-baseline justify-between mb-4">
        <h1 className="text-xl font-semibold text-gray-800">CVEs</h1>
        <div className="text-sm text-gray-500">
          {page ? `${page.totalElements} CVEs, page ${page.number + 1}/${Math.max(page.totalPages, 1)}` : ''}
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
            <th className="px-2 py-1 border w-20">CVSS v3.1</th>
            <th className="px-2 py-1 border w-16">
              <button
                type="button"
                onClick={() => onSortToggle('kev')}
                className="font-semibold hover:underline"
              >
                KEV{sort === 'kev' ? ' ↓' : ''}
              </button>
            </th>
            <th className="px-2 py-1 border w-20">
              <button
                type="button"
                onClick={() => onSortToggle('epss')}
                className="font-semibold hover:underline"
              >
                EPSS{sort === 'epss' ? ' ↓' : ''}
              </button>
            </th>
            <th className="px-2 py-1 border w-24">
              <button
                type="button"
                onClick={() => onSortToggle('composite')}
                className="font-semibold hover:underline"
              >
                Composite{sort === 'composite' ? ' ↓' : ''}
              </button>
            </th>
            <th className="px-2 py-1 border">Description</th>
            <th className="px-2 py-1 border w-32">Last Modified</th>
          </tr>
        </thead>
        <tbody>
          {page?.content.map((cve) => (
            <tr key={cve.cveId} className="border-b hover:bg-gray-50 select-none">
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
                {cve.epssScore !== null
                  ? `${(Number(cve.epssScore) * 100).toFixed(2)}%`
                  : <span className="text-gray-400">—</span>}
              </td>
              <td className={`px-2 py-1 border tabular-nums select-text ${severityClassFromString(cve.compositeScore)}`}>
                {cve.compositeScore !== null
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
          {!loading && page && page.content.length === 0 && (
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
    </div>
  );
}
