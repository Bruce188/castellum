import { useEffect, useState } from 'react';
import { api } from '../api/client';
import type {
  DiscoverySource,
  InterfaceInfo,
  PassiveDiscoveryResponse,
} from '../api/types';

interface Props {
  isAdmin: boolean;
}

const ALL_SOURCES: DiscoverySource[] = ['ARP', 'MDNS', 'PCAP'];
const FALLBACK_INTERFACES: InterfaceInfo[] = [
  { name: 'eth0', displayName: 'eth0', mtu: 1500 },
  { name: 'wlan0', displayName: 'wlan0', mtu: 1500 },
];

/**
 * ADMIN-only passive-discovery control panel.
 *
 * <p>Renders read-only (controls disabled, no submit) for VIEWERs so they can see
 * what an ADMIN would be able to trigger — the backend enforces RBAC regardless.
 * Wires {@code POST /api/discovery/passive} and {@code GET /api/discovery/interfaces}.
 * Falls back to {@code eth0/wlan0} if the interfaces endpoint returns empty or errors.
 */
export function DiscoveryControlPanel({ isAdmin }: Props) {
  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>(FALLBACK_INTERFACES);
  const [iface, setIface] = useState<string>('eth0');
  const [windowSeconds, setWindowSeconds] = useState<number>(30);
  const [sources, setSources] = useState<DiscoverySource[]>(['ARP', 'MDNS']);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<PassiveDiscoveryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api.listInterfaces()
      .then(list => {
        if (cancelled) return;
        if (list.length > 0) {
          setInterfaces(list);
          setIface(list[0].name);
        }
      })
      .catch(() => { /* keep fallback */ });
    return () => { cancelled = true; };
  }, []);

  function toggleSource(src: DiscoverySource) {
    setSources(prev =>
      prev.includes(src) ? prev.filter(s => s !== src) : [...prev, src]
    );
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!isAdmin || submitting) return;
    setSubmitting(true);
    setError(null);
    setResult(null);
    try {
      const out = await api.discoverPassive({
        iface,
        durationSeconds: windowSeconds,
        sources,
      });
      setResult(out);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'discovery failed');
    } finally {
      setSubmitting(false);
    }
  }

  const formDisabled = !isAdmin || submitting;
  return (
    <section
      data-testid="discovery-control-panel"
      className="rounded border border-gray-200 bg-white p-4 mb-4"
    >
      <header className="flex items-baseline justify-between mb-3">
        <h2 className="text-base font-semibold text-gray-800">Passive discovery</h2>
        {!isAdmin && (
          <span className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded px-2 py-0.5">
            Read-only — ADMIN required to run sweeps
          </span>
        )}
      </header>
      <form onSubmit={handleSubmit} className="grid gap-3 sm:grid-cols-2">
        <label className="text-sm">
          <span className="block text-gray-700 mb-1">Interface</span>
          <select
            data-testid="iface-select"
            value={iface}
            onChange={e => setIface(e.target.value)}
            disabled={formDisabled}
            className="w-full border border-gray-300 rounded px-2 py-1 text-sm disabled:bg-gray-50 disabled:text-gray-500"
          >
            {interfaces.map(i => (
              <option key={i.name} value={i.name}>{i.displayName || i.name}</option>
            ))}
          </select>
        </label>
        <label className="text-sm">
          <span className="block text-gray-700 mb-1">Window (seconds)</span>
          <input
            type="number"
            data-testid="window-seconds-input"
            min={5}
            max={300}
            value={windowSeconds}
            onChange={e => setWindowSeconds(Number(e.target.value))}
            disabled={formDisabled}
            className="w-full border border-gray-300 rounded px-2 py-1 text-sm disabled:bg-gray-50 disabled:text-gray-500"
          />
        </label>
        <fieldset className="sm:col-span-2">
          <legend className="text-sm text-gray-700 mb-1">Sources</legend>
          <div className="flex gap-4">
            {ALL_SOURCES.map(src => (
              <label key={src} className="text-sm flex items-center gap-1">
                <input
                  type="checkbox"
                  data-testid={`source-${src.toLowerCase()}`}
                  checked={sources.includes(src)}
                  onChange={() => toggleSource(src)}
                  disabled={formDisabled}
                />
                <span>{src}</span>
              </label>
            ))}
          </div>
        </fieldset>
        <div className="sm:col-span-2 flex items-center gap-3">
          <button
            type="submit"
            disabled={formDisabled || sources.length === 0}
            className="px-3 py-1 text-sm rounded bg-blue-600 text-white hover:bg-blue-700 disabled:bg-blue-300 disabled:cursor-not-allowed"
          >
            {submitting ? 'Running…' : 'Run passive discovery'}
          </button>
          {error && (
            <span role="alert" className="text-sm text-red-600">{error}</span>
          )}
        </div>
      </form>
      {result && (
        <div className="mt-4">
          <h3 className="text-sm font-semibold text-gray-800 mb-2">
            Discovered {result.discovered} neighbor{result.discovered === 1 ? '' : 's'}
            {result.sweepId != null && (
              <span className="ml-2 text-xs text-gray-500">sweep #{result.sweepId}</span>
            )}
          </h3>
          <table data-testid="discovery-results" className="w-full text-sm border border-gray-200">
            <thead className="bg-gray-50 text-left text-gray-700">
              <tr>
                <th className="px-2 py-1 border-b border-gray-200">Source</th>
                <th className="px-2 py-1 border-b border-gray-200">Count</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(result.perSourceCount).map(([src, count]) => (
                <tr key={src} className="border-b border-gray-100 last:border-0">
                  <td className="px-2 py-1">{src}</td>
                  <td className="px-2 py-1">{count}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {result.deviceIds.length > 0 && (
            <p className="mt-2 text-xs text-gray-600">
              Upserted device IDs: {result.deviceIds.join(', ')}
            </p>
          )}
        </div>
      )}
    </section>
  );
}
