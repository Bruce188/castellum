import { useEffect, useMemo, useState, type ReactElement } from 'react';
import { DevicePicker } from '../components/DevicePicker';
import { TopologyView } from '../components/TopologyView';
import { type HighlightPath, makeEdgeKey, EDGE_STYLES } from '../components/topologyConstants';
import { RiskTierKey } from '../components/RiskTierKey';
import { api } from '../api/client';
import type { ApiError } from '../api/client';
import type { Device, DeviceRiskDto, HopDto, ShortestPathResponse } from '../api/types';
import { displayIp } from '../lib/ipDisplay';

/**
 * Degrade copy for the backend's 503 GRAPH_TOO_LARGE response. Composed here
 * (rather than passing the backend message through verbatim) so the operator
 * gets an explanation plus a concrete next step.
 */
const GRAPH_TOO_LARGE_MESSAGE =
  'The attack graph is too large to compute: the fleet exceeds the configured ' +
  'device limit. Narrow the device scope or raise castellum.graph.max-devices.';

/**
 * Maps an unknown rejection to operator-facing error copy.
 *
 * <p>Total over any rejection value — a nullish or non-object rejection must
 * still land in the generic branch, not crash the caller. Gates on the body
 * code alone (not the HTTP status) so this stays in agreement with the
 * client's no-retry carve-out, which fires on any of 502/503/504 — a
 * status-rewriting proxy must not yield no-retry plus generic copy. When the
 * backend supplied actionable detail (actual device count / configured cap)
 * in {@code body.message}, it is appended to the composed degrade copy.
 */
function describeApiError(err: unknown, fallback: string): string {
  const apiErr = (typeof err === 'object' && err !== null ? err : {}) as Partial<ApiError>;
  if (apiErr.body?.error === 'GRAPH_TOO_LARGE') {
    const detail = typeof apiErr.body.message === 'string' && apiErr.body.message.length > 0
      ? ` (${apiErr.body.message})`
      : '';
    return GRAPH_TOO_LARGE_MESSAGE + detail;
  }
  return err instanceof Error ? err.message : fallback;
}

const EDGE_KEY_ENTRIES: ReadonlyArray<{ key: keyof typeof EDGE_STYLES; label: string }> = [
  { key: 'subnet',       label: 'Subnet link' },
  { key: 'gateway',      label: 'Gateway hub' },
  { key: 'dockerBridge', label: 'Docker bridge' },
  { key: 'attackPath',   label: 'Attack path' },
];

interface Props {
  /** When false, render an ADMIN-required notice and no controls. */
  isAdmin: boolean;
}

/**
 * Attack-Graph Explorer page.
 *
 * <p>ADMIN-only because computing a reachable exploit path between two devices
 * is a sensitive read. VIEWER sees an informational notice.
 *
 * <p>UX flow:
 * <ol>
 *   <li>Two {@link DevicePicker} inputs let the operator choose source and target.</li>
 *   <li>"Compute path" calls {@code GET /api/graph/shortest-path} via {@link api#shortestPath}.</li>
 *   <li>On success the topology view (right pane) overlays the path with the
 *       {@code path-highlight} class; the bottom pane renders a numbered
 *       breakdown — one step per hop — including edge type and (when the edge
 *       was {@code EXPLOITABLE_VULN}) the underlying CVE id and MITRE
 *       ATT&CK technique.</li>
 *   <li>{@code pathFound: false} renders a friendly "no reachable path" notice.</li>
 * </ol>
 */
export function AttackGraphPage({ isAdmin }: Props) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [risksById, setRisksById] = useState<Map<number, DeviceRiskDto>>(new Map());
  const [risksLoading, setRisksLoading] = useState<boolean>(false);
  const [fromId, setFromId] = useState<number | null>(null);
  const [toId, setToId] = useState<number | null>(null);
  const [response, setResponse] = useState<ShortestPathResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isAdmin) return;
    let cancelled = false;
    (async () => {
      setRisksLoading(true);
      try {
        const page = await api.listDevices();
        if (cancelled) return;
        setDevices(page.content);
        const map = await api.deviceRisksBatch(page.content.map(d => d.id));
        if (cancelled) return;
        setRisksById(map);
      } catch (err) {
        if (!cancelled) setError(describeApiError(err, 'load failed'));
      } finally {
        if (!cancelled) setRisksLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [isAdmin]);

  const hostnameById = useMemo(() => {
    const m = new Map<number, string>();
    for (const d of devices) m.set(d.id, d.hostname ?? displayIp(d.ipAddress));
    return m;
  }, [devices]);

  const highlight: HighlightPath | null = useMemo(() => {
    if (!response || !response.pathFound) return null;
    if (fromId === null) return null;
    const nodeIds: number[] = [fromId, ...response.hops.map(h => h.deviceId)];
    const edgeKeys: string[] = [];
    for (let i = 0; i < nodeIds.length - 1; i++) {
      edgeKeys.push(makeEdgeKey(nodeIds[i], nodeIds[i + 1]));
    }
    return { nodeIds, edgeKeys };
  }, [response, fromId]);

  async function handleCompute() {
    if (fromId === null || toId === null) return;
    setLoading(true);
    setError(null);
    setResponse(null);
    try {
      const result = await api.shortestPath({ from: fromId, to: toId });
      setResponse(result);
    } catch (err) {
      setError(describeApiError(err, 'compute failed'));
    } finally {
      setLoading(false);
    }
  }

  if (!isAdmin) {
    return (
      <div className="p-6">
        <h2 className="text-lg font-semibold mb-2">Attack Graph Explorer</h2>
        <p
          data-testid="attack-graph-admin-required"
          className="text-sm text-gray-700"
        >
          ADMIN role required to compute attack paths. Contact an administrator if you
          need access.
        </p>
      </div>
    );
  }

  const renderHopRow = (hop: HopDto, idx: number, prevId: number, prevLabel: string) => {
    const toLabel = hostnameById.get(hop.deviceId) ?? displayIp(hop.ipAddress);
    const techniqueText = hop.attackTechniqueId
      ? ` (technique: ${hop.attackTechniqueId}${hop.attackTechniqueName ? ` / ${hop.attackTechniqueName}` : ''})`
      : '';
    const cveText = hop.cveId ? ` (CVE: ${hop.cveId})` : '';
    return (
      <li
        key={`${prevId}-${hop.deviceId}-${idx}`}
        data-testid={`attack-graph-step-${idx + 1}`}
        className="py-1.5"
      >
        <span className="font-medium">Step {idx + 1}:</span>{' '}
        <span className="font-mono">{prevLabel}</span>{' '}
        <span className="text-gray-500">→</span>{' '}
        <span className="font-mono">{toLabel}</span>{' '}
        <span className="text-xs uppercase text-gray-600">via {hop.edgeType}</span>
        {cveText && <span className="text-xs text-red-700">{cveText}</span>}
        {techniqueText && <span className="text-xs text-gray-500">{techniqueText}</span>}
      </li>
    );
  };

  return (
    <div className="flex flex-col gap-4 p-4 h-full overflow-auto">
      <section className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold">Attack Graph Explorer</h2>
        <p className="text-xs text-gray-600">
          Compute the shortest exploit path between two devices in the Castellum
          attack graph. Edges are weighted by composite risk; lower-cost paths
          are easier for an attacker to traverse.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <DevicePicker
            devices={devices}
            value={fromId}
            onChange={setFromId}
            placeholder="From — hostname or IP"
            label="From"
            testId="attack-graph-from"
          />
          <DevicePicker
            devices={devices}
            value={toId}
            onChange={setToId}
            placeholder="To — hostname or IP"
            label="To"
            testId="attack-graph-to"
          />
        </div>
        <div>
          <button
            type="button"
            data-testid="attack-graph-compute-btn"
            disabled={loading || fromId === null || toId === null || fromId === toId}
            onClick={handleCompute}
            className="px-3 py-2 bg-slate-800 text-white text-sm rounded disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Computing path...' : 'Compute path'}
          </button>
          {fromId !== null && toId !== null && fromId === toId && (
            <p className="text-xs text-amber-700 mt-1" data-testid="attack-graph-same-device">
              Pick two different devices.
            </p>
          )}
        </div>
        {error && (
          <p className="text-sm text-red-600" data-testid="attack-graph-error">
            {error}
          </p>
        )}
        {response && response.pathFound && (
          <div data-testid="attack-graph-breakdown">
            <h3 className="text-sm font-semibold mt-2 mb-1">
              Path ({response.totalHops} {response.totalHops === 1 ? 'hop' : 'hops'}
              {response.cumulativeRisk ? `, cumulative risk ${response.cumulativeRisk}` : ''})
            </h3>
            <ol className="text-sm divide-y divide-gray-100 border border-gray-200 rounded">
              {response.hops.reduce<{ rows: ReactElement[]; prevId: number; prevLabel: string }>(
                (acc, hop, idx) => {
                  const row = renderHopRow(hop, idx, acc.prevId, acc.prevLabel);
                  return {
                    rows: [...acc.rows, row],
                    prevId: hop.deviceId,
                    prevLabel: hostnameById.get(hop.deviceId) ?? displayIp(hop.ipAddress),
                  };
                },
                {
                  rows: [],
                  prevId: fromId ?? response.from,
                  prevLabel:
                    hostnameById.get(fromId ?? response.from) ??
                    String(fromId ?? response.from),
                }
              ).rows}
            </ol>
          </div>
        )}
        {response && !response.pathFound && (
          <p
            data-testid="attack-graph-no-path"
            className="text-sm text-gray-700 border border-gray-200 rounded p-3 bg-gray-50"
          >
            No reachable attack path between selected devices.
          </p>
        )}
      </section>
      <section className="relative h-[600px] border border-gray-200 rounded bg-gray-50">
        <TopologyView
          devices={devices}
          risksById={risksById}
          risksLoading={risksLoading}
          onNodeClick={() => {
            // Read-only overlay — clicks are intentionally ignored on this page.
          }}
          onBackgroundClick={() => { /* noop */ }}
          highlightPath={highlight}
        />
        <div className="absolute top-2 right-2 bg-white/95 border border-gray-200 rounded shadow-sm p-2 text-xs space-y-2 z-10">
          <RiskTierKey />
          <ul data-testid="attack-graph-edge-key" className="space-y-1">
            {EDGE_KEY_ENTRIES.map(({ key, label }) => (
              <li key={key} className="flex items-center gap-2">
                <span
                  data-testid={`edge-swatch-${key}`}
                  className="inline-block w-3 h-3 rounded-sm"
                  style={{ backgroundColor: EDGE_STYLES[key].color }}
                  aria-hidden="true"
                />
                <span>{label}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>
    </div>
  );
}
