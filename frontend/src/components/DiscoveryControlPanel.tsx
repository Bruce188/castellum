import { useEffect, useRef, useState } from 'react';
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
 *
 * <p>AC1: one primary "Activate passive scanning" button with all-defaults payload.
 * AC2: collapsed Advanced section holds the iface select + source checkboxes + window input.
 * AC3: active/inactive state via in-flight submitting flag; deactivate via AbortController.abort().
 */
export function DiscoveryControlPanel({ isAdmin }: Props) {
  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>(FALLBACK_INTERFACES);
  const [iface, setIface] = useState<string>('');
  const [windowSeconds, setWindowSeconds] = useState<number>(30);
  const [sources, setSources] = useState<DiscoverySource[]>(ALL_SOURCES);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<PassiveDiscoveryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [advancedOpen, setAdvancedOpen] = useState(false);

  // AbortController ref for the in-flight request (AC3)
  const abortControllerRef = useRef<AbortController | null>(null);

  // Mounted guard — mirrors the `cancelled` pattern in listInterfaces useEffect
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  useEffect(() => {
    let cancelled = false;
    api.listInterfaces()
      .then(list => {
        if (cancelled) return;
        if (list.length > 0) {
          setInterfaces(list);
          // Do NOT set iface — keep blank (all-interfaces default)
        }
      })
      .catch(() => { /* keep fallback interfaces */ });
    return () => { cancelled = true; };
  }, []);

  function toggleSource(src: DiscoverySource) {
    setSources(prev =>
      prev.includes(src) ? prev.filter(s => s !== src) : [...prev, src]
    );
  }

  async function handleActivate() {
    if (!isAdmin || submitting) return;

    const controller = new AbortController();
    abortControllerRef.current = controller;

    setSubmitting(true);
    setError(null);
    setResult(null);

    try {
      const out = await api.discoverPassive(
        {
          iface,
          durationSeconds: windowSeconds,
          sources,
        },
        controller.signal
      );
      if (mountedRef.current) {
        setResult(out);
      }
    } catch (err) {
      // Swallow AbortError — user-initiated stop, no error banner
      if (err instanceof Error && err.name === 'AbortError') {
        // finally still runs; no error banner needed
      } else if (mountedRef.current) {
        setError(err instanceof Error ? err.message : 'discovery failed');
      }
    } finally {
      abortControllerRef.current = null;
      if (mountedRef.current) {
        setSubmitting(false);
      }
    }
  }

  function handleDeactivate() {
    abortControllerRef.current?.abort();
  }

  // Derive scan scope label for display
  const scopeIsDefault = iface === '' && sources.length === ALL_SOURCES.length &&
    ALL_SOURCES.every(s => sources.includes(s));
  const scopeLabel = scopeIsDefault
    ? 'all'
    : [
        iface ? `iface: ${iface}` : 'all interfaces',
        `sources: ${sources.join(', ')}`,
      ].join(' · ');

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

      {/* AC3 — status + scope line */}
      <div className="flex items-center gap-4 mb-3 text-sm">
        <span data-testid="scan-status" className={submitting ? 'text-green-700 font-medium' : 'text-gray-500'}>
          {submitting ? 'Active — scanning…' : 'Inactive'}
        </span>
        <span data-testid="scan-scope" className="text-gray-500">
          {scopeLabel}
        </span>
      </div>

      {/* AC1 — primary activate button + deactivate while in-flight */}
      <div className="flex items-center gap-3 mb-3">
        {!submitting ? (
          <button
            type="button"
            data-testid="passive-activate-btn"
            disabled={formDisabled || sources.length === 0}
            onClick={handleActivate}
            className="px-3 py-1 text-sm rounded bg-blue-600 text-white hover:bg-blue-700 disabled:bg-blue-300 disabled:cursor-not-allowed"
          >
            Activate passive scanning
          </button>
        ) : (
          <>
            {/* Keep the activate button in DOM but disabled while scanning, for testid consistency */}
            <button
              type="button"
              data-testid="passive-activate-btn"
              disabled
              className="px-3 py-1 text-sm rounded bg-blue-300 text-white cursor-not-allowed"
            >
              Scanning…
            </button>
            <button
              type="button"
              data-testid="passive-deactivate-btn"
              onClick={handleDeactivate}
              className="px-3 py-1 text-sm rounded bg-red-600 text-white hover:bg-red-700"
            >
              Deactivate
            </button>
          </>
        )}
        {error && (
          <span role="alert" className="text-sm text-red-600">{error}</span>
        )}
      </div>

      {/* AC2 — Advanced section (collapsed by default) */}
      <div className="mb-3">
        <button
          type="button"
          data-testid="advanced-toggle"
          aria-expanded={advancedOpen}
          onClick={() => setAdvancedOpen(prev => !prev)}
          className="text-sm text-blue-600 hover:underline"
        >
          {advancedOpen ? 'Hide advanced' : 'Advanced'}
        </button>

        {advancedOpen && (
          <div className="mt-3 grid gap-3 sm:grid-cols-2 border border-gray-100 rounded p-3 bg-gray-50">
            <label className="text-sm">
              <span className="block text-gray-700 mb-1">Interface</span>
              <select
                data-testid="iface-select"
                value={iface}
                onChange={e => setIface(e.target.value)}
                disabled={formDisabled}
                className="w-full border border-gray-300 rounded px-2 py-1 text-sm disabled:bg-gray-50 disabled:text-gray-500"
              >
                <option value="">— all interfaces —</option>
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
          </div>
        )}
      </div>

      {/* Results table (preserved) */}
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
