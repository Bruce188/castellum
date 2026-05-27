import { Fragment, useEffect, useState } from 'react';
import { api } from '../api/client';
import type { FeedsStatusDto, TopRiskDeviceDto } from '../api/types';
import { freshnessTier, FRESHNESS_BADGE_CLASSES, FRESHNESS_DOT_CLASSES } from '../lib/freshness';
import { RelatedCvesPanel } from './RelatedCvesPanel';

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
export function ThreatsDashboard() {
  const [state, setState] = useState<State>(INITIAL);
  const [expandedDeviceId, setExpandedDeviceId] = useState<number | null>(null);

  const toggleDeviceRow = (deviceId: number) => {
    setExpandedDeviceId(prev => prev === deviceId ? null : deviceId);
  };

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      if (cancelled) return;
      setState(INITIAL);
      try {
        const [top, feeds] = await Promise.all([api.topRisk(10), api.feedsStatus()]);
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
  }, []);

  const kevTotal = state.top.reduce((acc, d) => acc + d.kevCount, 0);
  const tier = freshnessTier(state.feeds?.epss?.scoreDate ?? null);

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

      {state.error && (
        <div className="text-sm text-red-600">{state.error}</div>
      )}

      {state.loading && !state.error && (
        <div className="text-sm text-gray-400">Loading…</div>
      )}

      {!state.loading && !state.error && state.top.length === 0 && (
        <p className="text-sm text-gray-500">No devices ranked yet. Run a scan to populate the fleet.</p>
      )}

      {!state.loading && state.top.length > 0 && (
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="text-left border-b text-gray-600">
              <th className="py-1 pr-2">#</th>
              <th className="py-1 pr-2">Host</th>
              <th
                className="py-1 pr-2"
                title="Operator-set field (LOW / MEDIUM / HIGH / CRITICAL) used as one input to the composite risk score. Distinct from the topology node color, which reflects the live composite tier."
              >
                Criticality
              </th>
              <th className="py-1 pr-2">KEV</th>
              <th className="py-1 pr-2 text-right">Composite</th>
            </tr>
          </thead>
          <tbody>
            {state.top.map((d, i) => (
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
                      <RelatedCvesPanel
                        deviceId={d.deviceId}
                        hostname={d.hostname}
                        ipAddress={d.ipAddress}
                      />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
