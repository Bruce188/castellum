import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import type { Criticality, Device, DeviceRiskDto, FeedsStatusDto, NetworkService, TopRiskDeviceDto } from '../api/types';
import { freshnessTier, FRESHNESS_BADGE_CLASSES, FRESHNESS_DOT_CLASSES } from '../lib/freshness';
import { CveDetailPanel } from './CveDetailPanel';
import { DeviceDetailPanel } from './DeviceDetailPanel';
import { RelatedCvesPanel } from './RelatedCvesPanel';

type ThreatSortKey = 'composite' | 'kev' | 'criticality' | 'host';
type SortDir = 'asc' | 'desc';

function isThreatSortKey(s: string): s is ThreatSortKey {
  return s === 'composite' || s === 'kev' || s === 'criticality' || s === 'host';
}

function isSortDir(s: string): s is SortDir {
  return s === 'asc' || s === 'desc';
}

const CRITICALITY_RANK: Record<Criticality, number> = {
  LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3,
};

/** Default sort direction for each key: high-risk keys default desc, label keys default asc. */
function defaultDir(key: ThreatSortKey): SortDir {
  return key === 'composite' || key === 'kev' ? 'desc' : 'asc';
}

interface State {
  loading: boolean;
  error: string | null;
  top: TopRiskDeviceDto[];
  feeds: FeedsStatusDto | null;
}

const INITIAL: State = { loading: true, error: null, top: [], feeds: null };

/**
 * Top-of-fleet threat surface. Renders the top-N at-risk devices ranked by composite
 * risk score, the fleet-wide count of KEV-flagged CVEs (summed from the rendered rows),
 * and a traffic-light freshness badge driven by the EPSS / KEV / NVD ingestion timestamps.
 *
 * <p>Single fetch on mount; not auto-refreshing. Operators trigger refreshes via the
 * existing scan / sync surfaces, then page-reload or click "Refresh" (when added).
 *
 * <p><b>v3-F2:</b> Row click now toggles an inline {@link RelatedCvesPanel} sub-row
 * instead of navigating to {@code /cves?deviceId=...}. The previous deep-link path
 * is preserved as a "View all in CVE explorer" anchor inside the expanded panel.
 * Only one row may be expanded at a time — expanding a second row collapses the first.
 */
export function ThreatsDashboard({ isAdmin = false }: { isAdmin?: boolean } = {}) {
  const [searchParams, setSearchParams] = useSearchParams();
  const [state, setState] = useState<State>(INITIAL);
  const [expandedDeviceId, setExpandedDeviceId] = useState<number | null>(null);
  // F-threats-cve-detail-drawer: selected CVE drives the shared CveDetailPanel drawer.
  const [selectedCveId, setSelectedCveId] = useState<string | null>(null);

  // feat/threats-open-device-detail: device+risk+services fetched lazily on row open.
  // deviceDetail holds the last-fetched data; deviceDetailVisible tracks whether the
  // inline DeviceDetailPanel is shown (operator can close it independently).
  const [deviceDetail, setDeviceDetail] = useState<{
    device: Device;
    risk: DeviceRiskDto | null;
    services: NetworkService[];
  } | null>(null);
  const [deviceDetailVisible, setDeviceDetailVisible] = useState(false);

  // --- Sort URL state ---
  const sortKeyParam = searchParams.get('sort') ?? 'composite';
  const sortKey: ThreatSortKey = isThreatSortKey(sortKeyParam) ? sortKeyParam : 'composite';
  const dirParam = searchParams.get('dir');
  // When dir is absent, fall back to the current key's sensible default (desc for
  // composite/kev, asc for host/criticality) rather than unconditionally 'desc'.
  const dir: SortDir = dirParam !== null && isSortDir(dirParam) ? dirParam : defaultDir(sortKey);

  const onSortToggle = (key: ThreatSortKey) => {
    setSearchParams(prev => {
      const params = new URLSearchParams(prev);
      if (key === sortKey) {
        // Flip direction on the active key
        const nextDir: SortDir = dir === 'desc' ? 'asc' : 'desc';
        // Omit when hitting the all-defaults state (composite + desc)
        if (key === 'composite' && nextDir === 'desc') {
          params.delete('sort');
          params.delete('dir');
        } else {
          params.set('sort', key);
          if (nextDir === defaultDir(key)) params.delete('dir');
          else params.set('dir', nextDir);
        }
      } else {
        const nd = defaultDir(key);
        if (key === 'composite' && nd === 'desc') {
          params.delete('sort');
          params.delete('dir');
        } else {
          params.set('sort', key);
          params.delete('dir'); // new key always starts at its default dir
        }
      }
      return params;
    });
  };

  // --- Row-count URL state ---
  const limitParam = searchParams.get('limit') ?? '10';
  const limitNum = Number(limitParam);
  const limit: 10 | 25 | 50 = (limitNum === 25 || limitNum === 50) ? limitNum : 10;

  const onLimitChange = (next: 10 | 25 | 50) => {
    setSearchParams(prev => {
      const params = new URLSearchParams(prev);
      if (next === 10) params.delete('limit');
      else params.set('limit', String(next));
      return params;
    });
  };

  // --- Filter URL state ---
  const critParam = searchParams.get('crit') ?? 'all';
  const crit: Criticality | 'all' = (critParam === 'LOW' || critParam === 'MEDIUM' || critParam === 'HIGH' || critParam === 'CRITICAL') ? critParam : 'all';
  const kevOnly = searchParams.get('kevOnly') === 'true';
  const host = searchParams.get('host') ?? '';

  const onCriticalityChange = (next: Criticality | 'all') => {
    setSearchParams(prev => {
      const params = new URLSearchParams(prev);
      if (next === 'all') params.delete('crit');
      else params.set('crit', next);
      return params;
    });
  };

  const onKevOnlyToggle = () => {
    setSearchParams(prev => {
      const params = new URLSearchParams(prev);
      if (kevOnly) params.delete('kevOnly');
      else params.set('kevOnly', 'true');
      return params;
    });
  };

  const onHostFilterChange = (next: string) => {
    setSearchParams(prev => {
      const params = new URLSearchParams(prev);
      if (next === '') params.delete('host');
      else params.set('host', next);
      return params;
    });
  };

  const [deviceDetailError, setDeviceDetailError] = useState(false);
  // Monotonic counter used to discard resolutions from superseded requests (rapid
  // row switching). Captures token at call start; ignores if a newer fetch fired.
  const fetchTokenRef = useRef(0);

  // Fetch device+risk+services lazily when a row is opened.
  const fetchDeviceDetail = useCallback(async (deviceId: number) => {
    fetchTokenRef.current += 1;
    const myToken = fetchTokenRef.current;
    setDeviceDetailError(false);
    try {
      const [device, risk, services] = await Promise.all([
        api.getDevice(deviceId),
        api.deviceRisk(deviceId),
        api.listServicesForDevice(deviceId),
      ]);
      if (myToken !== fetchTokenRef.current) return; // superseded
      setDeviceDetail({ device, risk, services });
      setDeviceDetailVisible(true);
    } catch {
      if (myToken !== fetchTokenRef.current) return; // superseded
      // Surface the failure inline so the operator can retry without losing context.
      setDeviceDetail(null);
      setDeviceDetailVisible(false);
      setDeviceDetailError(true);
    }
  }, []);

  const toggleDeviceRow = (deviceId: number) => {
    setExpandedDeviceId(prev => {
      const next = prev === deviceId ? null : deviceId;
      // Close the CVE drawer when collapsing the threat row or switching rows.
      if (next !== prev) setSelectedCveId(null);
      if (next === null) {
        // Row collapsed — hide device detail too.
        setDeviceDetailVisible(false);
        setDeviceDetail(null);
        setDeviceDetailError(false);
      } else {
        // Row opened (or switched) — trigger lazy fetch.
        void fetchDeviceDetail(next);
      }
      return next;
    });
  };

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      if (cancelled) return;
      setState(INITIAL);
      try {
        // Re-fetching feedsStatus on a limit change is acceptable and keeps the
        // freshness badge fresh; the extra round-trip is negligible.
        const [top, feeds] = await Promise.all([api.topRisk(limit), api.feedsStatus()]);
        if (cancelled) return;
        // Defensive: backend returns an array; if for any reason the response shape
        // is malformed (test stubs, error pages), collapse to empty rather than crash.
        setState({ loading: false, error: null, top: Array.isArray(top) ? top : [], feeds });
      } catch (err) {
        if (cancelled) return;
        setState({
          loading: false,
          error: err instanceof Error ? err.message : 'Failed to load threats dashboard',
          top: [],
          feeds: null,
        });
      }
    };
    void load();
    return () => { cancelled = true; };
  }, [limit]);

  const kevTotal = state.top.reduce((acc, d) => acc + d.kevCount, 0);
  const tier = freshnessTier(state.feeds?.epss?.scoreDate ?? null);

  // Client-side filter + sort over the fetched rows — never refetches.
  const visibleRows = useMemo(() => {
    // Step 1: filter
    const filtered = state.top.filter(d => {
      if (crit !== 'all' && d.criticality !== crit) return false;
      if (kevOnly && d.kevCount === 0) return false;
      if (host !== '') {
        const hostLower = host.toLowerCase();
        const match = (d.hostname ?? '').toLowerCase().includes(hostLower) ||
          d.ipAddress.toLowerCase().includes(hostLower);
        if (!match) return false;
      }
      return true;
    });
    // Step 2: sort
    const primaryCmp = (a: TopRiskDeviceDto, b: TopRiskDeviceDto): number => {
      if (sortKey === 'composite') return Number(a.score) - Number(b.score);
      if (sortKey === 'kev') return a.kevCount - b.kevCount;
      if (sortKey === 'criticality') {
        return (CRITICALITY_RANK[a.criticality] ?? 0) - (CRITICALITY_RANK[b.criticality] ?? 0);
      }
      // host: localeCompare over hostname ?? ipAddress
      return (a.hostname ?? a.ipAddress).localeCompare(b.hostname ?? b.ipAddress);
    };
    const comparator = (a: TopRiskDeviceDto, b: TopRiskDeviceDto): number => {
      const cmp = primaryCmp(a, b);
      const withTiebreak = cmp === 0 ? a.deviceId - b.deviceId : cmp;
      return dir === 'asc' ? withTiebreak : -withTiebreak;
    };
    return filtered.sort(comparator);
  }, [state.top, crit, kevOnly, host, sortKey, dir]);

  return (
    <section className="rounded border bg-white p-4 space-y-3 m-2" data-testid="threats-dashboard">
      <header className="flex items-center justify-between flex-wrap gap-2">
        <h2 className="font-semibold text-gray-700">Threats Overview</h2>
        <div className="flex items-center gap-3 text-sm">
          <span
            data-testid="freshness-badge"
            className={`inline-flex items-center gap-1 px-2 py-0.5 border rounded text-xs ${FRESHNESS_BADGE_CLASSES[tier]}`}
            title={state.feeds?.epss?.scoreDate
              ? `EPSS scoreDate: ${state.feeds.epss.scoreDate}`
              : 'EPSS feed has not been ingested'}
          >
            <span className={`inline-block w-2 h-2 rounded-full ${FRESHNESS_DOT_CLASSES[tier]}`} />
            Feeds: {tier}
          </span>
          <span className="text-gray-600">
            <strong className="text-gray-900">{kevTotal}</strong> KEV-flagged CVEs in top-{state.top.length || 'N'}
          </span>
        </div>
      </header>

      {/* Controls row: criticality filter + KEV-only toggle + host text filter */}
      <div className="flex items-center gap-2 flex-wrap text-sm">
        <select
          data-testid="threats-crit-select"
          value={crit}
          onChange={(e) => onCriticalityChange(e.target.value as Criticality | 'all')}
          className="border rounded px-2 py-1"
        >
          <option value="all">All criticalities</option>
          <option value="LOW">LOW</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="HIGH">HIGH</option>
          <option value="CRITICAL">CRITICAL</option>
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
          data-testid="threats-host-filter"
          type="text"
          placeholder="Filter by host / IP…"
          value={host}
          onChange={(e) => onHostFilterChange(e.target.value)}
          className="border rounded px-2 py-1 text-sm"
        />
        <select
          data-testid="threats-limit-select"
          value={limit}
          onChange={(e) => onLimitChange(Number(e.target.value) as 10 | 25 | 50)}
          className="border rounded px-2 py-1"
        >
          <option value={10}>Top 10</option>
          <option value={25}>Top 25</option>
          <option value={50}>Top 50</option>
        </select>
      </div>

      {state.error && (
        <div className="text-sm text-red-600">{state.error}</div>
      )}

      {state.loading && !state.error && (
        <div
          data-testid="threats-loading"
          className="flex items-center justify-center gap-2 py-8 text-sm text-gray-500"
        >
          <span className="inline-block h-4 w-4 rounded-full border-2 border-gray-300 border-t-gray-600 animate-spin" />
          Loading threat overview…
        </div>
      )}

      {!state.loading && !state.error && state.top.length === 0 && (
        <p className="text-sm text-gray-500">No devices ranked yet. Run a scan to populate the fleet.</p>
      )}

      {!state.loading && state.top.length > 0 && (
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="text-left border-b text-gray-600">
              <th className="py-1 pr-2">#</th>
              <th className="py-1 pr-2">
                <button
                  type="button"
                  data-testid="sort-host"
                  onClick={() => onSortToggle('host')}
                  className="font-semibold hover:underline"
                >
                  Host{sortKey === 'host' ? (dir === 'asc' ? ' ↑' : ' ↓') : ''}
                </button>
              </th>
              <th
                className="py-1 pr-2"
                title="Operator-set field (LOW / MEDIUM / HIGH / CRITICAL) used as one input to the composite risk score. Distinct from the topology node color, which reflects the live composite tier."
              >
                <button
                  type="button"
                  data-testid="sort-criticality"
                  onClick={() => onSortToggle('criticality')}
                  className="font-semibold hover:underline"
                >
                  Criticality{sortKey === 'criticality' ? (dir === 'asc' ? ' ↑' : ' ↓') : ''}
                </button>
              </th>
              <th className="py-1 pr-2">
                <button
                  type="button"
                  data-testid="sort-kev"
                  onClick={() => onSortToggle('kev')}
                  className="font-semibold hover:underline"
                >
                  KEV{sortKey === 'kev' ? (dir === 'asc' ? ' ↑' : ' ↓') : ''}
                </button>
              </th>
              <th className="py-1 pr-2 text-right">
                <button
                  type="button"
                  data-testid="sort-composite"
                  onClick={() => onSortToggle('composite')}
                  className="font-semibold hover:underline"
                >
                  Composite{sortKey === 'composite' ? (dir === 'asc' ? ' ↑' : ' ↓') : ''}
                </button>
              </th>
            </tr>
          </thead>
          <tbody>
            {state.top.length > 0 && visibleRows.length === 0 && (
              <tr>
                <td colSpan={5} className="py-4 text-center text-sm text-gray-500 italic">
                  No threats match these filters.
                </td>
              </tr>
            )}
            {visibleRows.map((d, i) => (
              <Fragment key={d.deviceId}>
                <tr
                  role="button"
                  tabIndex={0}
                  data-testid={`threats-row-${d.deviceId}`}
                  aria-expanded={expandedDeviceId === d.deviceId}
                  onClick={() => toggleDeviceRow(d.deviceId)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      toggleDeviceRow(d.deviceId);
                    }
                  }}
                  className="border-b cursor-pointer hover:bg-gray-50 focus:bg-gray-50 focus:outline-none"
                >
                  <td className="py-1 pr-2 text-gray-500">{i + 1}</td>
                  <td className="py-1 pr-2">
                    <div className="font-mono">{d.hostname ?? d.ipAddress}</div>
                    {d.hostname && (
                      <div className="text-xs text-gray-500">{d.ipAddress}</div>
                    )}
                  </td>
                  <td className="py-1 pr-2">{d.criticality}</td>
                  <td className="py-1 pr-2">
                    {d.kevCount > 0 ? (
                      <span className="inline-block px-1 rounded bg-red-100 text-red-800 text-xs">
                        {d.kevCount}
                      </span>
                    ) : (
                      <span className="text-gray-400">—</span>
                    )}
                  </td>
                  <td className="py-1 pr-2 text-right font-mono">{d.score}</td>
                </tr>
                {expandedDeviceId === d.deviceId && (
                  <tr data-testid={`threats-related-panel-${d.deviceId}`}>
                    <td colSpan={5} className="p-0">
                      {/* Inline device detail: rendered above related CVEs so the operator
                          sees device context first. Uses variant="inline" so the panel
                          renders in normal document flow rather than as a fixed-position
                          overlay — the 'drawer' default would pin to the viewport at the
                          same coordinates as the F7 CveDetailPanel drawer (both z-20). */}
                      {deviceDetailVisible && deviceDetail && (
                        <div className="border-b border-gray-200">
                          <DeviceDetailPanel
                            variant="inline"
                            device={deviceDetail.device}
                            risk={deviceDetail.risk}
                            services={deviceDetail.services}
                            isAdmin={isAdmin}
                            onClose={() => setDeviceDetailVisible(false)}
                            onDeviceMutated={() => void fetchDeviceDetail(d.deviceId)}
                          />
                        </div>
                      )}
                      {deviceDetailError && !deviceDetailVisible && (
                        <div
                          data-testid="device-detail-error"
                          className="px-4 py-2 text-sm text-red-600 bg-red-50 border-b border-red-100"
                        >
                          Could not load device detail — retry
                        </div>
                      )}
                      <RelatedCvesPanel
                        deviceId={d.deviceId}
                        hostname={d.hostname}
                        ipAddress={d.ipAddress}
                        onCveSelect={setSelectedCveId}
                      />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}

      {/* CVE detail drawer — same component/UX as /cves page (feat/threats-cve-detail-drawer) */}
      <CveDetailPanel
        cveId={selectedCveId}
        onClose={() => setSelectedCveId(null)}
      />
    </section>
  );
}
