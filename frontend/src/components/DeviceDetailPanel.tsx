import type { Device, DeviceRiskDto, NetworkService } from '../api/types';
import { toRiskTier, tierColor } from '../lib/riskTier';

interface Props {
  device: Device | null;
  risk: DeviceRiskDto | null;
  services: NetworkService[];
  onClose: () => void;
}

export function DeviceDetailPanel({ device, risk, services, onClose }: Props) {
  if (device === null) return null;

  const score = risk ? Number(risk.score) : null;
  const tier = toRiskTier(score);

  return (
    <aside
      data-testid="device-detail-panel"
      className="fixed right-0 top-0 h-screen w-96 bg-white shadow-lg overflow-y-auto p-4 border-l border-gray-200"
    >
      <header className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-lg font-semibold">{device.hostname ?? device.ipAddress}</h2>
          <p className="text-sm text-gray-500">{device.ipAddress}</p>
        </div>
        <button
          type="button"
          aria-label="Close panel"
          onClick={onClose}
          className="text-gray-500 hover:text-gray-900 px-2 py-1"
        >
          &times;
        </button>
      </header>

      <section className="mb-4">
        <div className="flex items-center gap-2 mb-2">
          <span
            className="inline-block w-3 h-3 rounded-full"
            style={{ backgroundColor: tierColor[tier] }}
          />
          <span className="text-sm font-medium uppercase">{tier}</span>
          <span className="ml-auto text-2xl font-bold">
            {score === null ? '—' : score.toFixed(2)}
          </span>
        </div>
      </section>

      <section className="mb-4">
        <h3 className="text-sm font-semibold mb-1">Device</h3>
        <dl className="text-sm grid grid-cols-[max-content_1fr] gap-x-2 gap-y-1">
          <dt className="text-gray-500">id</dt><dd>{device.id}</dd>
          <dt className="text-gray-500">criticality</dt><dd>{device.criticality}</dd>
          <dt className="text-gray-500">mac</dt><dd>{device.macAddress ?? '—'}</dd>
          <dt className="text-gray-500">first seen</dt><dd>{device.firstSeen ?? '—'}</dd>
          <dt className="text-gray-500">last seen</dt><dd>{device.lastSeen ?? '—'}</dd>
        </dl>
      </section>

      <section className="mb-4">
        <h3 className="text-sm font-semibold mb-1">Services ({services.length})</h3>
        {services.length === 0 ? (
          <p className="text-sm text-gray-500">No services observed.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500">
                <th>port</th><th>proto</th><th>name</th><th>ver</th>
              </tr>
            </thead>
            <tbody>
              {services.map(s => (
                <tr key={s.id}>
                  <td>{s.port}</td>
                  <td>{s.protocol}</td>
                  <td>{s.name ?? '—'}</td>
                  <td>{s.version ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section>
        <h3 className="text-sm font-semibold mb-1">Top CVEs</h3>
        {risk && risk.topCveIds.length > 0 ? (
          <ul className="text-sm list-disc pl-5">
            {risk.topCveIds.map(id => <li key={id}>{id}</li>)}
          </ul>
        ) : (
          <p className="text-sm text-gray-500">No matched CVEs.</p>
        )}
      </section>
    </aside>
  );
}
