import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import type { CveDetailDto, CveAffectedDevice } from '../api/types';
import { CvssVectorBreakdown } from './CvssVectorBreakdown';

interface NvdReference {
  url: string;
  source?: string;
  tags?: string[];
}

// References are parsed client-side from the already-shipped rawJson (avoiding a structured
// references[] field on CveDetailDto), with an NVD-canonical URL as fallback when absent.
function parseReferences(rawJson: string | null | undefined): NvdReference[] {
  try {
    if (!rawJson) return [];
    const parsed = JSON.parse(rawJson);
    const refs: NvdReference[] =
      parsed?.vulnerabilities?.[0]?.cve?.references ?? [];
    return Array.isArray(refs) && refs.length > 0 ? refs : [];
  } catch {
    return [];
  }
}

function nvdFallback(cveId: string): NvdReference {
  return { url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`, source: 'NVD' };
}

function isSpareDetail(detail: CveDetailDto): boolean {
  return (
    !detail.description &&
    !detail.cvssV31Score &&
    !detail.cvssV30Score &&
    !detail.cvssV2Score &&
    !detail.epssScore &&
    !detail.compositeScore &&
    !detail.kev
  );
}

interface Props {
  cveId: string | null;
  onClose: () => void;
}

export function CveDetailPanel({ cveId, onClose }: Props) {
  const [detail, setDetail] = useState<CveDetailDto | null>(null);
  const [detailError, setDetailError] = useState(false);
  const [affected, setAffected] = useState<CveAffectedDevice[]>([]);
  const [affectedError, setAffectedError] = useState(false);
  const [loading, setLoading] = useState(false);

  // Session-scoped cache of fully-loaded CVE details + affected-device lists,
  // keyed by cveId. Re-opening a CVE already viewed in this CvesPage session is
  // served synchronously from the ref — no second round-trip for the multi-KB
  // detail payload or the (uncached, full-fleet-scan) /devices endpoint. The
  // cache is component-scoped (a useRef, not a module global) so it resets on
  // unmount and never leaks across renders or test mounts. Only fully-successful
  // pairs are cached, so a partial/failed load still retries on re-open.
  const cacheRef = useRef<Map<string, { detail: CveDetailDto; affected: CveAffectedDevice[] }>>(
    new Map(),
  );

  useEffect(() => {
    if (!cveId) {
      setDetail(null);
      setDetailError(false);
      setAffected([]);
      setAffectedError(false);
      setLoading(false);
      return;
    }

    const cached = cacheRef.current.get(cveId);
    if (cached) {
      setDetail(cached.detail);
      setAffected(cached.affected);
      setDetailError(false);
      setAffectedError(false);
      setLoading(false);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setDetailError(false);
    setAffectedError(false);
    Promise.allSettled([api.cveDetail(cveId), api.listAffectedDevices(cveId)])
      .then(([detailResult, affectedResult]) => {
        if (cancelled) return;
        const okDetail = detailResult.status === 'fulfilled' ? detailResult.value : null;
        const okAffected = affectedResult.status === 'fulfilled' ? affectedResult.value : null;

        if (okDetail !== null) {
          setDetail(okDetail);
        } else {
          setDetail(null);
          setDetailError(true);
        }
        if (okAffected !== null) {
          setAffected(okAffected);
        } else {
          setAffected([]);
          setAffectedError(true);
        }
        // Cache only when BOTH calls succeeded — a partial failure must re-fetch
        // on the next open rather than serving a half-populated panel forever.
        if (okDetail !== null && okAffected !== null) {
          cacheRef.current.set(cveId, { detail: okDetail, affected: okAffected });
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [cveId]);

  if (!cveId) return null;

  const refs = detail ? parseReferences(detail.rawJson) : [];
  const displayRefs = refs.length > 0 ? refs : [nvdFallback(cveId)];

  return (
    <aside
      data-testid="cve-detail-panel"
      className="fixed right-0 top-0 z-20 h-screen w-96 bg-white shadow-lg overflow-y-auto p-4 border-l border-gray-200"
    >
      <header className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold font-mono">{cveId}</h2>
        <button
          type="button"
          aria-label="Close CVE panel"
          onClick={onClose}
          className="text-gray-500 hover:text-gray-900 px-2 py-1"
        >
          &times;
        </button>
      </header>

      {loading && <p className="text-sm text-gray-500">Loading…</p>}

      {detailError && (
        <p className="text-sm text-red-600">Couldn't load CVE detail.</p>
      )}

      {detail && (
        <>
          <section className="mb-4">
            <div className="flex flex-wrap gap-2 mb-2">
              {detail.kev && (
                <span className="bg-red-100 text-red-700 rounded px-2 py-0.5 text-xs font-semibold">
                  KEV
                </span>
              )}
              {detail.cvssV31Score && (
                <span className="bg-orange-100 text-orange-800 rounded px-2 py-0.5 text-xs font-semibold">
                  CVSS <span>{detail.cvssV31Score}</span>
                </span>
              )}
              {detail.epssScore && (
                <span className="bg-purple-100 text-purple-800 rounded px-2 py-0.5 text-xs">
                  EPSS {(Number(detail.epssScore) * 100).toFixed(1)}%
                </span>
              )}
              {detail.compositeScore && (
                <span className="bg-gray-100 text-gray-800 rounded px-2 py-0.5 text-xs">
                  Composite {Number(detail.compositeScore).toFixed(2)}
                </span>
              )}
            </div>
            {isSpareDetail(detail) ? (
              <p className="text-sm text-gray-500">No additional detail available for this CVE yet.</p>
            ) : (
              <p className="text-sm text-gray-700">{detail.description ?? 'No description.'}</p>
            )}
          </section>

          {detail.cvssV31Vector && (
            <section className="mb-4">
              <h3 className="text-sm font-semibold mb-1">CVSS Vector</h3>
              <CvssVectorBreakdown
                vector={detail.cvssV31Vector}
                score={detail.cvssV31Score}
              />
            </section>
          )}

          <section className="mb-4">
            <h3 className="text-sm font-semibold mb-1">References</h3>
            <ul className="space-y-1">
              {displayRefs.map((ref, i) => (
                <li key={i} className="text-xs">
                  <a
                    href={ref.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-600 hover:underline break-all"
                  >
                    {ref.url}
                  </a>
                  {ref.source && (
                    <span className="ml-1 text-gray-400">({ref.source})</span>
                  )}
                </li>
              ))}
            </ul>
          </section>

          <section>
            <h3 className="text-sm font-semibold mb-1">Affected Devices</h3>
            {affectedError ? (
              <p className="text-sm text-red-500">Couldn't load affected devices.</p>
            ) : affected.length === 0 ? (
              <p className="text-sm text-gray-500">No affected devices found in this fleet.</p>
            ) : (
              <ul className="space-y-1">
                {affected.map((d) => (
                  <li key={d.deviceId} className="text-xs border rounded p-2">
                    <Link
                      to={`/cves?deviceId=${d.deviceId}`}
                      className="font-medium text-blue-700 hover:underline"
                    >
                      {d.hostname ?? d.ipAddress}
                    </Link>
                    <span className="ml-1 text-gray-500">{d.ipAddress}</span>
                    <div className="text-gray-400">
                      {d.matchedService} :{d.matchedPort}
                      {d.matchedVersion ? ` v${d.matchedVersion}` : ''}
                    </div>
                    {/* AC1: matched CPE product+version and version range that caused the match */}
                    {d.matchedCpe && (
                      <div
                        data-testid="matched-cpe"
                        className="text-gray-400 font-mono break-all mt-0.5"
                        title="NVD CPE that matched this service"
                      >
                        {d.matchedCpe}
                      </div>
                    )}
                    {(d.matchedRangeStart || d.matchedRangeEnd) && (
                      <div
                        data-testid="matched-range"
                        className="text-gray-400 mt-0.5"
                      >
                        Range:{' '}
                        {d.matchedRangeStart ? `${d.matchedRangeStart} – ` : ''}
                        {d.matchedRangeEnd ?? ''}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </aside>
  );
}
