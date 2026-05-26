import type { Criticality, Device, DeviceRiskDto, NetworkService } from '../api/types';
import { toRiskTier, tierColor } from '../lib/riskTier';
import { CveEvidenceTable } from './CveEvidenceTable';
import { WhyScorePanel } from './WhyScorePanel';
import { CriticalityInlineEdit } from './CriticalityInlineEdit';
import { HostnameInlineEdit } from './HostnameInlineEdit';
import { DecommissionButton } from './DecommissionButton';
import { api } from '../api/client';

interface Props {
  device: Device | null;
  risk: DeviceRiskDto | null;
  services: NetworkService[];
  onClose: () => void;
  /** When true, render inline-edit + decommission controls. Defaults to {@code false}. */
  isAdmin?: boolean;
  /** Called after a successful PUT/DELETE so the parent can refetch its device list. */
  onDeviceMutated?: () => void;
}

export function DeviceDetailPanel({ device, risk, services, onClose, isAdmin = false, onDeviceMutated }: Props) {
  if (device === null) return null;

  const score = risk ? Number(risk.score) : null;
  const tier = toRiskTier(score);

  async function handleCriticalitySave(next: Criticality) {
    if (device === null) return;
    await api.updateDevice(device.id, device, { criticality: next });
    onDeviceMutated?.();
  }

  async function handleHostnameSave(next: string) {
    if (device === null) return;
    await api.updateDevice(device.id, device, { hostname: next });
    onDeviceMutated?.();
  }

  async function handleDecommission() {
    if (device === null) return;
    await api.deleteDevice(device.id);
    onDeviceMutated?.();
    onClose();
  }

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
            {Number.isFinite(score) ? (score as number).toFixed(2) : '—'}
          </span>
        </div>
      </section>

      <section className="mb-4">
        <h3 className="text-sm font-semibold mb-1">Device</h3>
        <dl className="text-sm grid grid-cols-[max-content_1fr] gap-x-2 gap-y-1">
          <dt className="text-gray-500">id</dt><dd>{device.id}</dd>
          <dt className="text-gray-500">hostname</dt>
          <dd>
            <HostnameInlineEdit
              value={device.hostname}
              isAdmin={isAdmin}
              onSave={handleHostnameSave}
            />
          </dd>
          <dt className="text-gray-500">criticality</dt>
          <dd>
            <CriticalityInlineEdit
              value={device.criticality}
              isAdmin={isAdmin}
              onSave={handleCriticalitySave}
            />
          </dd>
          <dt className="text-gray-500">mac</dt><dd>{device.macAddress ?? '—'}</dd>
          <dt className="text-gray-500">first seen</dt><dd>{device.firstSeen ?? '—'}</dd>
          <dt className="text-gray-500">last seen</dt><dd>{device.lastSeen ?? '—'}</dd>
        </dl>
        {isAdmin && (
          <div className="mt-3">
            <DecommissionButton
              device={device}
              isAdmin={isAdmin}
              onConfirmed={handleDecommission}
            />
          </div>
        )}
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

      <section className="mb-4">
        <h3 className="text-sm font-semibold mb-1">CVE Evidence</h3>
        <CveEvidenceTable cveIds={risk?.topCveIds ?? []} />
      </section>

      {risk?.components && (
        <section className="mb-4">
          <WhyScorePanel risk={risk} />
        </section>
      )}
    </aside>
  );
}
