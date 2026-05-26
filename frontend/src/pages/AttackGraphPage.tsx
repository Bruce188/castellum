import { useEffect, useMemo, useState, type ReactElement } from 'react';
import { DevicePicker } from '../components/DevicePicker';
import { TopologyView, type HighlightPath, makeEdgeKey } from '../components/TopologyView';
import { api } from '../api/client';
import type { Device, DeviceRiskDto, HopDto, ShortestPathResponse } from '../api/types';

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
  const [fromId, setFromId] = useState<number | null>(null);
  const [toId, setToId] = useState<number | null>(null);
  const [response, setResponse] = useState<ShortestPathResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isAdmin) return;
    let cancelled = false;
    (async () => {
      try {
        const page = await api.listDevices();
        if (cancelled) return;
        setDevices(page.content);
        const results = await Promise.allSettled(
          page.content.map(d => api.deviceRisk(d.id))
        );
        if (cancelled) return;
        const map = new Map<number, DeviceRiskDto>();
        results.forEach((r, i) => {
          if (r.status === 'fulfilled') map.set(page.content[i].id, r.value);
        });
        setRisksById(map);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'load failed');
      }
    })();
    return () => { cancelled = true; };
  }, [isAdmin]);

  const hostnameById = useMemo(() => {
    const m = new Map<number, string>();
    for (const d of devices) m.set(d.id, d.hostname ?? d.ipAddress);
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
      setError(err instanceof Error ? err.message : 'compute failed');
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
    const toLabel = hostnameById.get(hop.deviceId) ?? hop.ipAddress;
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
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 p-4 h-full overflow-auto">
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
                    prevLabel: hostnameById.get(hop.deviceId) ?? hop.ipAddress,
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
      <section className="min-h-[400px] border border-gray-200 rounded bg-gray-50">
        <TopologyView
          devices={devices}
          risksById={risksById}
          onNodeClick={() => {
            // Read-only overlay — clicks are intentionally ignored on this page.
          }}
          onBackgroundClick={() => { /* noop */ }}
          highlightPath={highlight}
        />
      </section>
    </div>
  );
}
