import { useCallback, useEffect, useState } from 'react';
import { api } from '../api/client';
import type { CveSummaryDto, Page } from '../api/types';

const PAGE_SIZE = 25;

type SeverityFilter = 'all' | 'high' | 'critical';

const SEVERITY_THRESHOLDS: Record<Exclude<SeverityFilter, 'all'>, number> = {
  high: 7.0,
  critical: 9.0,
};

function severityClass(score: string | null): string {
  if (!score) return 'text-gray-500';
  const n = Number(score);
  if (n >= 9.0) return 'text-red-700 font-semibold';
  if (n >= 7.0) return 'text-orange-600 font-medium';
  if (n >= 4.0) return 'text-amber-600';
  return 'text-gray-600';
}

export function CvesPage() {
  const [page, setPage] = useState<Page<CveSummaryDto> | null>(null);
  const [pageNumber, setPageNumber] = useState(0);
  const [severity, setSeverity] = useState<SeverityFilter>('all');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchPage = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const minScore = severity === 'all' ? undefined : SEVERITY_THRESHOLDS[severity];
      const result = await api.listFleetCves(pageNumber, PAGE_SIZE, minScore);
      setPage(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load CVEs');
      setPage(null);
    } finally {
      setLoading(false);
    }
  }, [pageNumber, severity]);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      if (cancelled) return;
      setLoading(true);
      setError(null);
      try {
        const minScore = severity === 'all' ? undefined : SEVERITY_THRESHOLDS[severity];
        const result = await api.listFleetCves(pageNumber, PAGE_SIZE, minScore);
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
  }, [pageNumber, severity]);

  const onSeverityChange = (next: SeverityFilter) => {
    setSeverity(next);
    setPageNumber(0);
  };

  return (
    <div className="h-full overflow-auto p-6">
      <div className="flex items-baseline justify-between mb-4">
        <h1 className="text-xl font-semibold text-gray-800">CVEs</h1>
        <div className="text-sm text-gray-500">
          {page ? `${page.totalElements} CVEs, page ${page.number + 1}/${Math.max(page.totalPages, 1)}` : ''}
        </div>
      </div>

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
            <th className="px-2 py-1 border">Description</th>
            <th className="px-2 py-1 border w-32">Last Modified</th>
          </tr>
        </thead>
        <tbody>
          {page?.content.map((cve) => (
            <tr key={cve.cveId} className="border-b hover:bg-gray-50">
              <td className="px-2 py-1 border font-mono text-xs">{cve.cveId}</td>
              <td className={`px-2 py-1 border tabular-nums ${severityClass(cve.cvssV31Score)}`}>
                {cve.cvssV31Score ?? '—'}
              </td>
              <td className="px-2 py-1 border text-gray-700 truncate max-w-xl">
                {cve.description ?? <span className="text-gray-400">no description</span>}
              </td>
              <td className="px-2 py-1 border text-xs text-gray-600 tabular-nums">
                {cve.lastModified?.slice(0, 10)}
              </td>
            </tr>
          ))}
          {!loading && page && page.content.length === 0 && (
            <tr>
              <td colSpan={4} className="px-2 py-4 text-center text-gray-500 italic">
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
            onClick={() => setPageNumber((n) => Math.max(n - 1, 0))}
            className="border rounded px-2 py-1 disabled:opacity-40"
          >
            Prev
          </button>
          <button
            type="button"
            disabled={pageNumber + 1 >= page.totalPages}
            onClick={() => setPageNumber((n) => n + 1)}
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
