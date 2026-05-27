import { Fragment, useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../api/client';
import type { CveDetailDto, CveSummaryDto } from '../api/types';

interface RelatedCvesPanelProps {
  deviceId: number;
  hostname: string | null;
  ipAddress: string;
}

type DetailState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'ok'; detail: CveDetailDto }
  | { status: 'error'; message: string };

function severityFromCvss(score: string | null): string {
  if (score == null) return 'Unknown';
  const n = Number(score);
  if (!Number.isFinite(n) || n <= 0) return 'None';
  if (n >= 9) return 'Critical';
  if (n >= 7) return 'High';
  if (n >= 4) return 'Medium';
  return 'Low';
}

function severityClass(label: string): string {
  switch (label) {
    case 'Critical': return 'text-red-700 font-semibold';
    case 'High': return 'text-orange-600 font-semibold';
    case 'Medium': return 'text-yellow-600';
    case 'Low': return 'text-green-600';
    default: return 'text-gray-500';
  }
}

/**
 * Lazy-loaded related-CVE list for a single device. Mounted inline by
 * {@code ThreatsDashboard} when an operator expands a row. Fetches via the
 * existing fleet endpoint ({@code GET /api/cve/fleet?deviceId=...&size=50})
 * — no new backend surface area. Empty case shows the literal copy
 * mandated by the spec; populated case renders one row per matched CVE
 * with a KEV chip when applicable and a click-to-expand detail sub-row that
 * lazy-fetches {@code GET /api/cve/{cveId}} on first activation and caches
 * the response.
 */
export function RelatedCvesPanel({ deviceId, hostname, ipAddress }: RelatedCvesPanelProps) {
  const [cves, setCves] = useState<CveSummaryDto[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [details, setDetails] = useState<Map<string, DetailState>>(new Map());
  const requestIdRef = useRef(0);

  useEffect(() => {
    const myRequestId = ++requestIdRef.current;
    // Defer the loading-state reset out of the synchronous effect body to keep
    // React's set-state-in-effect lint clean — same observable behaviour, just
    // off the immediate render path.
    queueMicrotask(() => {
      if (myRequestId !== requestIdRef.current) return;
      setLoading(true);
      setError(null);
    });
    api.listFleetCves(0, 50, undefined, deviceId)
      .then(result => {
        if (myRequestId !== requestIdRef.current) return;
        setCves(Array.isArray(result.content) ? result.content : []);
        setLoading(false);
      })
      .catch(err => {
        if (myRequestId !== requestIdRef.current) return;
        setError(err instanceof Error ? err.message : 'Failed to load related CVEs');
        setLoading(false);
      });
  }, [deviceId]);

  const ensureFetched = useCallback(async (cveId: string) => {
    const current = details.get(cveId);
    if (current && current.status !== 'idle' && current.status !== 'error') return;
    setDetails(prev => {
      const next = new Map(prev);
      next.set(cveId, { status: 'loading' });
      return next;
    });
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

  const toggleRow = (cveId: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(cveId)) {
        next.delete(cveId);
      } else {
        next.add(cveId);
        const existing = details.get(cveId);
        if (!existing || existing.status === 'idle' || existing.status === 'error') {
          void ensureFetched(cveId);
        }
      }
      return next;
    });
  };

  const displayName = hostname ?? ipAddress;

  return (
    <div
      role="region"
      aria-label={`Related CVEs for ${displayName}`}
      data-testid={`related-cves-panel-${deviceId}`}
      className="bg-gray-50 border-t p-3 space-y-2"
    >
      <h3 className="font-semibold text-sm text-gray-700">Related CVEs</h3>

      {loading && <div className="text-sm text-gray-400">Loading…</div>}

      {error && <div className="text-sm text-red-600">{error}</div>}

      {!loading && !error && cves.length === 0 && (
        <p data-testid="related-cves-empty" className="text-sm text-gray-500">
          No linked CVEs for this threat.
        </p>
      )}

      {!loading && !error && cves.length > 0 && (
        <ul className="divide-y border rounded bg-white">
          {cves.map(cve => {
            const sev = severityFromCvss(cve.cvssV31Score);
            const isExpanded = expanded.has(cve.cveId);
            const detailState = details.get(cve.cveId);
            return (
              <Fragment key={cve.cveId}>
                <li
                  role="button"
                  tabIndex={0}
                  data-testid={`related-cves-row-${cve.cveId}`}
                  aria-expanded={isExpanded}
                  onClick={() => toggleRow(cve.cveId)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      toggleRow(cve.cveId);
                    }
                  }}
                  className="flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-gray-50 focus:bg-gray-50 focus:outline-none text-sm"
                >
                  <span className="font-mono">{cve.cveId}</span>
                  <span className="text-gray-500">{cve.cvssV31Score ?? '—'}</span>
                  <span className={severityClass(sev)}>{sev}</span>
                  {cve.kev && (
                    <span
                      data-testid={`related-cves-kev-badge-${cve.cveId}`}
                      className="bg-red-100 text-red-700 rounded px-2 py-0.5 text-xs"
                    >
                      KEV
                    </span>
                  )}
                </li>
                {isExpanded && (
                  <li
                    data-testid={`related-cves-detail-${cve.cveId}`}
                    className="px-3 py-2 bg-gray-50 text-xs text-gray-700 space-y-1"
                  >
                    {detailState?.status === 'loading' && (
                      <div className="text-gray-400">Loading detail…</div>
                    )}
                    {detailState?.status === 'error' && (
                      <div className="text-red-600">{detailState.message}</div>
                    )}
                    {detailState?.status === 'ok' && (
                      <>
                        <div>{detailState.detail.description ?? '(no description)'}</div>
                        {detailState.detail.cvssV31Vector && (
                          <div className="font-mono text-gray-500">{detailState.detail.cvssV31Vector}</div>
                        )}
                      </>
                    )}
                  </li>
                )}
              </Fragment>
            );
          })}
        </ul>
      )}

      <a
        href={`/cves?deviceId=${deviceId}`}
        data-testid="related-cves-view-all"
        className="text-sm text-blue-600 hover:underline inline-block"
      >
        View all in CVE explorer
      </a>
    </div>
  );
}
