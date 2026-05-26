import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import type { AuditEntry, AuditFilters } from '../api/types';

interface Props {
  isAdmin: boolean;
}

const ACTION_OPTIONS = [
  '', 'SCAN_SUBMIT', 'SCAN_COMPLETE', 'SCAN_FAILED',
  'DEVICE_CREATE', 'DEVICE_UPDATE', 'DEVICE_DELETE',
  'INITIAL_SYNC_TRIGGERED', 'RBAC_DENY',
  'THREAT_INTEL_PUSH', 'OT_PROBE', 'DISCOVERY_SWEEP',
] as const;

const RESOURCE_TYPE_OPTIONS = ['', 'device', 'scan', 'system', 'audit', 'service'] as const;

export default function AuditLogPanel({ isAdmin }: Props) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [totalElements, setTotalElements] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<AuditFilters>({ size: 50, page: 0 });
  const [pendingFilters, setPendingFilters] = useState<AuditFilters>({ size: 50, page: 0 });
  const [expandedRowId, setExpandedRowId] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await api.listAudit(filters);
        if (cancelled) return;
        setEntries(result.content);
        setTotalElements(result.totalElements);
        setTotalPages(result.totalPages);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Failed to load audit entries');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void run();
    return () => { cancelled = true; };
  }, [filters]);

  function handleApply() {
    setFilters({ ...pendingFilters, page: 0, size: 50 });
  }

  function handleRefresh() {
    setFilters(f => ({ ...f }));
  }

  async function handleDownloadCsv() {
    try {
      const blob = await api.downloadAuditCsv(filters);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit-log-${new Date().toISOString()}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'CSV download failed');
    }
  }

  function toggleRow(id: number) {
    setExpandedRowId(prev => (prev === id ? null : id));
  }

  function renderPayload(payload: string | null): string {
    if (!payload) return '(empty)';
    try {
      return JSON.stringify(JSON.parse(payload), null, 2);
    } catch {
      return payload;
    }
  }

  if (!isAdmin) return null;

  return (
    <section className="rounded border bg-white p-4 space-y-2 m-2">
      <h2 className="font-semibold text-gray-700">Audit Log</h2>

      {error && (
        <div className="text-red-600 text-sm">{error}</div>
      )}

      {/* Filter bar */}
      <div className="flex flex-wrap gap-2 items-end text-sm">
        <label className="flex flex-col gap-1">
          <span>Action</span>
          <select
            value={pendingFilters.action ?? ''}
            onChange={e => setPendingFilters(f => ({ ...f, action: e.target.value }))}
            className="border rounded px-1 py-0.5"
          >
            {ACTION_OPTIONS.map(opt => (
              <option key={opt} value={opt}>{opt || '(any)'}</option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span>Actor</span>
          <input
            type="text"
            value={pendingFilters.actor ?? ''}
            onChange={e => setPendingFilters(f => ({ ...f, actor: e.target.value }))}
            className="border rounded px-1 py-0.5 w-28"
            placeholder="any"
          />
        </label>

        <label className="flex flex-col gap-1">
          <span>Resource Type</span>
          <select
            value={pendingFilters.resourceType ?? ''}
            onChange={e => setPendingFilters(f => ({ ...f, resourceType: e.target.value }))}
            className="border rounded px-1 py-0.5"
          >
            {RESOURCE_TYPE_OPTIONS.map(opt => (
              <option key={opt} value={opt}>{opt || '(any)'}</option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span>Since</span>
          <input
            type="datetime-local"
            value={pendingFilters.since?.slice(0, 16) ?? ''}
            onChange={e => {
              const val = e.target.value;
              setPendingFilters(f => ({
                ...f,
                since: val ? new Date(val).toISOString() : undefined,
              }));
            }}
            className="border rounded px-1 py-0.5"
          />
        </label>

        <label className="flex flex-col gap-1">
          <span>Until</span>
          <input
            type="datetime-local"
            value={pendingFilters.until?.slice(0, 16) ?? ''}
            onChange={e => {
              const val = e.target.value;
              setPendingFilters(f => ({
                ...f,
                until: val ? new Date(val).toISOString() : undefined,
              }));
            }}
            className="border rounded px-1 py-0.5"
          />
        </label>

        <button
          type="button"
          onClick={handleApply}
          className="px-3 py-1 border border-blue-400 rounded text-blue-700 hover:bg-blue-50"
        >
          Apply
        </button>
        <button
          type="button"
          onClick={handleRefresh}
          className="px-3 py-1 border border-gray-300 rounded hover:bg-gray-100"
        >
          Refresh
        </button>
        <button
          type="button"
          onClick={handleDownloadCsv}
          className="px-3 py-1 border border-green-400 rounded text-green-700 hover:bg-green-50"
        >
          Download CSV
        </button>
      </div>

      {/* Table */}
      {loading && <div className="text-gray-400 text-sm">Loading…</div>}
      {!loading && entries.length === 0 && (
        <p className="text-gray-500 text-sm">No audit entries match the current filter.</p>
      )}
      {entries.length > 0 && (
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="text-left border-b text-gray-600">
              <th className="py-1 pr-2">Time</th>
              <th className="py-1 pr-2">Actor</th>
              <th className="py-1 pr-2">Action</th>
              <th className="py-1 pr-2">Resource Type</th>
              <th className="py-1 pr-2">Resource ID</th>
            </tr>
          </thead>
          <tbody>
            {entries.map(entry => (
              <React.Fragment key={entry.id}>
                <tr
                  onClick={() => toggleRow(entry.id)}
                  className="border-b hover:bg-gray-50 cursor-pointer"
                >
                  <td className="py-1 pr-2 font-mono text-xs">
                    {new Date(entry.occurredAt).toISOString()}
                  </td>
                  <td className="py-1 pr-2">{entry.actor}</td>
                  <td className="py-1 pr-2">{entry.action}</td>
                  <td className="py-1 pr-2">{entry.resourceType}</td>
                  <td className="py-1 pr-2">{entry.resourceId ?? '—'}</td>
                </tr>
                {expandedRowId === entry.id && (
                  <tr className="bg-gray-50">
                    <td colSpan={5} className="p-2">
                      <pre className="text-xs overflow-auto max-h-40 whitespace-pre-wrap">
                        {renderPayload(entry.payload)}
                      </pre>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      )}

      {/* Pagination */}
      <div className="flex items-center gap-3 text-sm text-gray-600">
        <button
          type="button"
          disabled={(filters.page ?? 0) <= 0}
          onClick={() => setFilters(f => ({ ...f, page: (f.page ?? 0) - 1 }))}
          className="px-2 py-0.5 border rounded disabled:opacity-40"
        >
          Prev
        </button>
        <span>
          Page {(filters.page ?? 0) + 1} of {totalPages || 1}
        </span>
        <button
          type="button"
          disabled={(filters.page ?? 0) >= totalPages - 1}
          onClick={() => setFilters(f => ({ ...f, page: (f.page ?? 0) + 1 }))}
          className="px-2 py-0.5 border rounded disabled:opacity-40"
        >
          Next
        </button>
        <span className="ml-2 text-gray-400">Total: {totalElements}</span>
      </div>
    </section>
  );
}
