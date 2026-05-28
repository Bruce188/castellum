import { useState, useCallback } from 'react';
import { api } from '../api/client';
import type { OtProbeResponse, OtProtocol } from '../api/types';

interface Props {
  isAdmin: boolean;
}

/**
 * Read-only OT/ICS fingerprint probe — never writes to the target. The protocol
 * dropdown lists only read-fingerprint identifiers (Modbus device-id, DNP3 link
 * layer, S7 SZL, BACnet who-is). The UI never sends a write request; the
 * backend's {@code OtFingerprintService} is the source of truth for that contract.
 *
 * <p>ADMIN-only writes: VIEWERs see the panel rendered read-only with controls
 * disabled. Backend RBAC enforces this regardless.
 */
interface ProtocolOption {
  value: OtProtocol;
  label: string;
  defaultPort: number;
}

const PROTOCOLS: ProtocolOption[] = [
  { value: 'MODBUS_TCP', label: 'Modbus/TCP', defaultPort: 502 },
  { value: 'DNP3', label: 'DNP3', defaultPort: 20000 },
  { value: 'S7COMM', label: 'S7comm', defaultPort: 102 },
  { value: 'BACNET_IP', label: 'BACnet/IP', defaultPort: 47808 },
];

type SweepCellStatus = 'pending' | 'in-flight' | 'success' | 'failed';

interface SweepCell {
  host: string;
  protocol: OtProtocol;
  port: number;
  status: SweepCellStatus;
  result?: OtProbeResponse;
  error?: string;
}

export function OtProbePanel({ isAdmin }: Props) {
  // --- single-protocol state ---
  const [host, setHost] = useState<string>('127.0.0.1');
  const [port, setPort] = useState<number>(502);
  const [protocol, setProtocol] = useState<OtProtocol>('MODBUS_TCP');
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<OtProbeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  // --- sweep state ---
  const [sweeping, setSweeping] = useState(false);
  const [sweepCells, setSweepCells] = useState<SweepCell[] | null>(null);
  const [sweepCompleted, setSweepCompleted] = useState(0);
  const [sweepTotal, setSweepTotal] = useState(0);

  function selectProtocol(next: OtProtocol) {
    setProtocol(next);
    const opt = PROTOCOLS.find(p => p.value === next);
    if (opt) setPort(opt.defaultPort);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!isAdmin || submitting) return;
    setSubmitting(true);
    setError(null);
    setResult(null);
    try {
      const out = await api.probeOt({ host, port, protocol });
      setResult(out);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'probe failed');
    } finally {
      setSubmitting(false);
    }
  }

  const handleSweep = useCallback(async () => {
    if (!isAdmin || sweeping) return;
    setSweeping(true);
    setSweepCells(null);
    setSweepCompleted(0);

    try {
      const page = await api.listDevices();
      const hosts = page.content.map((d) => d.ipAddress);
      const total = hosts.length * PROTOCOLS.length;
      setSweepTotal(total);

      // Build the initial cell matrix and show it immediately
      const matrix: SweepCell[] = hosts.flatMap((h) =>
        PROTOCOLS.map((p) => ({
          host: h,
          protocol: p.value,
          port: p.defaultPort,
          status: 'pending' as const,
        }))
      );
      setSweepCells([...matrix]);

      let settled = 0;

      // Fan-out: probe each host×protocol. Per-host serialization via sequential
      // await per host; hosts run concurrently across the outer Promise.all.
      await Promise.all(
        hosts.map(async (h) => {
          for (const proto of PROTOCOLS) {
            const cellIdx = matrix.findIndex(
              (c) => c.host === h && c.protocol === proto.value,
            );
            if (cellIdx >= 0) {
              matrix[cellIdx] = { ...matrix[cellIdx], status: 'in-flight' };
              setSweepCells([...matrix]);
            }

            try {
              const res = await api.probeOtOnce(h, proto.value, proto.defaultPort);
              if (cellIdx >= 0) {
                matrix[cellIdx] = {
                  ...matrix[cellIdx],
                  status: 'success',
                  result: res,
                };
              }
            } catch (err) {
              if (cellIdx >= 0) {
                matrix[cellIdx] = {
                  ...matrix[cellIdx],
                  status: 'failed',
                  error: err instanceof Error ? err.message : String(err),
                };
              }
            }

            settled++;
            setSweepCells([...matrix]);
            setSweepCompleted(settled);
          }
        }),
      );
    } finally {
      setSweeping(false);
    }
  }, [isAdmin, sweeping]);

  const formDisabled = !isAdmin || submitting;
  const sweepDisabled = !isAdmin || sweeping;

  return (
    <section
      data-testid="ot-probe-panel"
      className="rounded border border-gray-200 bg-white p-4 mb-4"
    >
      <header className="flex items-baseline justify-between mb-3">
        <h2 className="text-base font-semibold text-gray-800">OT/ICS fingerprint probe</h2>
        {!isAdmin && (
          <span className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded px-2 py-0.5">
            Read-only — ADMIN required to run probes
          </span>
        )}
      </header>
      <p className="text-xs text-gray-600 mb-3">
        Read-only fingerprint. The probe never writes to the target device — it only
        reads identification fields exposed by the protocol.
      </p>
      <p data-testid="ot-protocol-help" className="text-xs text-gray-500 mb-3">
        Checks four ICS protocols: Modbus/TCP (502), DNP3 (20000), S7comm (102), BACnet/IP (47808).
      </p>
      <p data-testid="ot-verify-help" className="text-xs text-gray-500 mb-3">
        A successful probe persists the device and an OT service, then shows vendor / product /
        version below (raw protocol fields — including the read-only unit/slave id — under the
        expander). Confirm it ran by opening the device in the topology detail panel: it flags an
        "OT/ICS protocols detected" indicator and an "ICS / OT" badge on the service row.
      </p>

      {/* AC1 — primary sweep button */}
      <div className="mb-4">
        <button
          type="button"
          data-testid="ot-sweep-all-btn"
          disabled={sweepDisabled}
          onClick={handleSweep}
          className="px-4 py-2 text-sm font-medium rounded bg-indigo-600 text-white hover:bg-indigo-700 disabled:bg-indigo-300 disabled:cursor-not-allowed"
        >
          {sweeping ? 'Sweeping…' : 'Probe all OT/ICS protocols'}
        </button>
      </div>

      {/* AC3 — progress tally + grid (rendered once sweep has been started) */}
      {sweepCells !== null && (
        <>
          <p data-testid="ot-sweep-progress" className="text-xs text-gray-600 mb-2">
            {sweepCompleted}/{sweepTotal}
          </p>
          <div data-testid="ot-sweep-grid" className="overflow-x-auto mb-4">
            <table className="text-xs border border-gray-200">
              <tbody>
                {sweepCells.map((cell: SweepCell) => (
                  <tr key={`${cell.host}-${cell.protocol}`}>
                    <td
                      data-testid={`ot-sweep-cell-${cell.host}-${cell.protocol}`}
                      className="px-2 py-1 border border-gray-100"
                    >
                      {cell.host} / {cell.protocol}: {cell.status}
                      {cell.result &&
                        ` — ${cell.result.vendor ?? ''} ${cell.result.product ?? ''}`}
                      {cell.error && ` — err: ${cell.error}`}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* AC4 — advanced single-protocol form under a disclosure toggle */}
      <details
        data-testid="ot-advanced-toggle"
        className="border border-gray-200 rounded p-3"
      >
        <summary className="text-sm font-medium text-gray-700 cursor-pointer select-none">
          Advanced — single-protocol probe
        </summary>
        <div className="mt-3">
          <form onSubmit={handleSubmit} className="grid gap-3 sm:grid-cols-3">
            <label className="text-sm sm:col-span-2">
              <span className="block text-gray-700 mb-1">Target host (IPv4)</span>
              <input
                type="text"
                data-testid="ot-host-input"
                value={host}
                onChange={e => setHost(e.target.value)}
                disabled={formDisabled}
                className="w-full border border-gray-300 rounded px-2 py-1 text-sm disabled:bg-gray-50 disabled:text-gray-500"
              />
            </label>
            <label className="text-sm">
              <span className="block text-gray-700 mb-1">Port</span>
              <input
                type="number"
                data-testid="ot-port-input"
                min={1}
                max={65535}
                value={port}
                onChange={e => setPort(Number(e.target.value))}
                disabled={formDisabled}
                className="w-full border border-gray-300 rounded px-2 py-1 text-sm disabled:bg-gray-50 disabled:text-gray-500"
              />
            </label>
            <label className="text-sm sm:col-span-2">
              <span className="block text-gray-700 mb-1">Protocol</span>
              <select
                data-testid="ot-protocol-select"
                value={protocol}
                onChange={e => selectProtocol(e.target.value as OtProtocol)}
                disabled={formDisabled}
                className="w-full border border-gray-300 rounded px-2 py-1 text-sm disabled:bg-gray-50 disabled:text-gray-500"
              >
                {PROTOCOLS.map(p => (
                  <option key={p.value} value={p.value}>{p.label}</option>
                ))}
              </select>
            </label>
            <div className="sm:col-span-3 flex items-center gap-3">
              <button
                type="submit"
                disabled={formDisabled}
                className="px-3 py-1 text-sm rounded bg-blue-600 text-white hover:bg-blue-700 disabled:bg-blue-300 disabled:cursor-not-allowed"
              >
                {submitting ? 'Probing…' : 'Run probe'}
              </button>
              {error && (
                <span role="alert" className="text-sm text-red-600">{error}</span>
              )}
            </div>
          </form>
          {result && (
            <div className="mt-4">
              <h3 className="text-sm font-semibold text-gray-800 mb-2">
                Fingerprint — {result.protocol} {result.host}:{result.port}
              </h3>
              <dl
                data-testid="ot-probe-result"
                className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm"
              >
                <dt className="text-gray-600">Vendor</dt>
                <dd>{result.vendor ?? <span className="text-gray-400">—</span>}</dd>
                <dt className="text-gray-600">Product</dt>
                <dd>{result.product ?? <span className="text-gray-400">—</span>}</dd>
                <dt className="text-gray-600">Version</dt>
                <dd>{result.version ?? <span className="text-gray-400">—</span>}</dd>
                <dt className="text-gray-600">Device ID</dt>
                <dd>{result.deviceId}</dd>
                <dt className="text-gray-600">Service ID</dt>
                <dd>{result.serviceId}</dd>
                <dt className="text-gray-600">Observed at</dt>
                <dd>{result.observedAt}</dd>
              </dl>
              {Object.keys(result.rawFields).length > 0 && (
                <details className="mt-3">
                  <summary className="text-xs text-gray-600 cursor-pointer">
                    Raw protocol fields ({Object.keys(result.rawFields).length})
                  </summary>
                  <table className="mt-2 w-full text-xs border border-gray-200">
                    <thead className="bg-gray-50 text-left text-gray-700">
                      <tr>
                        <th className="px-2 py-1 border-b border-gray-200">Key</th>
                        <th className="px-2 py-1 border-b border-gray-200">Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(result.rawFields).map(([k, v]) => (
                        <tr key={k} className="border-b border-gray-100 last:border-0">
                          <td className="px-2 py-1 font-mono">{k}</td>
                          <td className="px-2 py-1 font-mono">{v}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </details>
              )}
            </div>
          )}
        </div>
      </details>
    </section>
  );
}
