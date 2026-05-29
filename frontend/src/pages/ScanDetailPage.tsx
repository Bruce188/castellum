import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api } from '../api/client';
import { exportScanReportJson } from '../lib/scanReportExport';
import type { ScanReport } from '../api/types';

type ErrorKind = 'not-found' | 'other';

const DELTA_STYLE: Record<string, string> = {
  new: 'bg-green-100 text-green-800',
  changed: 'bg-yellow-100 text-yellow-800',
  unchanged: 'bg-gray-100 text-gray-600',
};

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const parsedId = id !== undefined ? Number(id) : NaN;
  const scanId = Number.isFinite(parsedId) ? parsedId : null;

  const [report, setReport] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState<boolean>(scanId !== null);
  const [error, setError] = useState<{ kind: ErrorKind } | null>(
    scanId === null ? { kind: 'not-found' } : null,
  );

  useEffect(() => {
    if (scanId === null) return;
    let cancelled = false;

    setLoading(true);
    setError(null);

    api.getScanReport(scanId)
      .then((data) => {
        if (cancelled) return;
        setReport(data);
      })
      .catch((err) => {
        if (cancelled) return;
        const msg = err instanceof Error ? err.message : '';
        setError({ kind: msg.startsWith('404') ? 'not-found' : 'other' });
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [scanId]);

  if (loading) {
    return (
      <div role="status" data-testid="scan-detail-loading" className="p-4">
        Loading scan…
      </div>
    );
  }

  if (error?.kind === 'not-found') {
    return (
      <div className="p-4">
        <div role="alert" data-testid="scan-detail-not-found" className="mb-3">
          Scan not found.
        </div>
        <Link to="/scans" className="text-blue-700 hover:underline">
          ← Back to scans
        </Link>
      </div>
    );
  }

  if (error?.kind === 'other' || report === null) {
    return (
      <div className="p-4">
        <div role="alert" className="mb-3">Failed to load scan.</div>
        <Link to="/scans" className="text-blue-700 hover:underline">
          ← Back to scans
        </Link>
      </div>
    );
  }

  const { summary, devices } = report;

  const durationSecs =
    summary.durationMillis != null
      ? (summary.durationMillis / 1000).toFixed(1) + 's'
      : '—';

  return (
    <div className="p-4">
      {/* Header */}
      <div className="mb-4 flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">Scan #{summary.scanId}</h1>
        <div className="flex gap-2">
          <button
            data-testid="report-download-json-btn"
            onClick={() => exportScanReportJson(report)}
            className="text-sm px-3 py-1 rounded border border-gray-300 hover:bg-gray-50"
          >
            Export JSON
          </button>
          <button
            data-testid="report-print-btn"
            onClick={() => window.print()}
            className="text-sm px-3 py-1 rounded border border-gray-300 hover:bg-gray-50"
          >
            Print / PDF
          </button>
          <Link to="/scans" className="text-blue-700 hover:underline text-sm self-center">
            ← Back to scans
          </Link>
        </div>
      </div>

      {/* Scan metadata */}
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm mb-4">
        <dt className="text-gray-500">CIDR</dt>
        <dd className="font-mono">{summary.cidr}</dd>
        <dt className="text-gray-500">Type</dt>
        <dd>{summary.scanType}</dd>
        <dt className="text-gray-500">Status</dt>
        <dd data-testid="scan-status">{summary.status}</dd>
        <dt className="text-gray-500">Requested at</dt>
        <dd>{summary.requestedAt}</dd>
        <dt className="text-gray-500">Completed at</dt>
        <dd>{summary.completedAt ?? '—'}</dd>
        <dt className="text-gray-500">Duration</dt>
        <dd>{durationSecs}</dd>
      </dl>

      {/* Summary counts */}
      <div
        data-testid="scan-summary-counts"
        className="flex gap-6 mb-6 text-sm bg-gray-50 rounded p-3"
      >
        <span><strong>{summary.deviceCount}</strong> devices</span>
        <span><strong>{summary.serviceCount}</strong> services</span>
        <span><strong>{summary.cveCount}</strong> CVEs</span>
      </div>

      {/* Snapshot table */}
      <section>
        <h2 className="text-lg font-semibold mb-2">Device snapshot</h2>
        {devices.length === 0 ? (
          <p className="text-sm text-gray-500">No devices in this scan.</p>
        ) : (
          <table className="w-full text-sm" data-testid="scan-snapshot-table">
            <thead>
              <tr className="text-left text-gray-500 border-b">
                <th className="py-1 pr-4">IP</th>
                <th className="py-1 pr-4">Hostname</th>
                <th className="py-1 pr-4">Services</th>
                <th className="py-1 pr-4">CVEs</th>
                <th className="py-1">Delta</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.id} className="border-b last:border-b-0">
                  <td className="py-1 pr-4 font-mono">{d.ipAddress}</td>
                  <td className="py-1 pr-4">{d.hostname ?? '—'}</td>
                  <td className="py-1 pr-4">{d.services.length}</td>
                  <td className="py-1 pr-4">{d.cveIds.length}</td>
                  <td className="py-1">
                    <span
                      data-testid={`delta-${d.delta}`}
                      className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${DELTA_STYLE[d.delta] ?? ''}`}
                    >
                      {d.delta}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
