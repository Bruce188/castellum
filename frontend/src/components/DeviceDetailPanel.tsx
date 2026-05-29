import type { Criticality, Device, DeviceRiskDto, NetworkService } from '../api/types';
import { toRiskTier, tierColor } from '../lib/riskTier';
import { scopeChipColor } from '../lib/scopeColors';
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
  /**
   * Rendering variant.
   *
   * - `'drawer'` (default): fixed right-side viewport overlay used by TopologyPage.
   * - `'inline'`: in-flow element with no fixed positioning, for use inside a table
   *   row (e.g. ThreatsDashboard) where a viewport overlay would collide with the
   *   F7 CveDetailPanel drawer sharing the same coordinates and z-index.
   */
  variant?: 'drawer' | 'inline';
}

export function DeviceDetailPanel({ device, risk, services, onClose, isAdmin = false, onDeviceMutated, variant = 'drawer' }: Props) {
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

  const rootClassName = variant === 'inline'
    ? 'relative w-full bg-white p-4 border-l-2 border-gray-200 overflow-y-auto'
    // z-20 lifts the panel above the TopologyLegend (z-10), which is pinned to
    // the same right edge; without it the legend floats on top of the panel
    // header when a node is selected.
    : 'fixed right-0 top-0 z-20 h-screen w-96 bg-white shadow-lg overflow-y-auto p-4 border-l border-gray-200';

  return (
    <aside
      data-testid="device-detail-panel"
      className={rootClassName}
    >
      <header className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-lg font-semibold">{device.hostname ?? device.ipAddress}</h2>
          <p className="text-sm text-gray-500">{device.ipAddress}</p>
          <span
            data-testid="scope-chip"
            style={{ backgroundColor: scopeChipColor[device.discoveryScope] }}
            className="inline-block text-xs px-2 py-0.5 rounded mt-1 text-white"
          >
            {device.discoveryScope}
          </span>
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
          {risk?.components?.kevPresent && (
            // v3-F1 — top-of-panel KEV exposure indicator. The "max composite"
            // half of features-runtime-fixes-v3 AC#4 is already satisfied by the
            // existing score badge above; this chip is the new prominent KEV signal.
            // (Decision 8 — chip-only, no DTO change.)
            <span
              data-testid="kev-exposure-chip"
              className="bg-red-100 text-red-700 rounded px-2 py-0.5 text-xs font-semibold ml-2"
            >
              KEV exposure
            </span>
          )}
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
          {device.lastSeenIface !== null && (
            <>
              <dt className="text-gray-500">last seen iface</dt>
              <dd>{device.lastSeenIface}</dd>
            </>
          )}
          <dt className="text-gray-500">discovered via</dt>
          <dd>{device.discoverySource ?? 'Unknown'}</dd>
          <dt className="text-gray-500">device role</dt>
          <dd data-testid="device-role">{device.deviceRole}</dd>
          <dt className="text-gray-500">OS</dt>
          <dd data-testid="device-os">
            {device.osName
              ? `${device.osName}${device.osAccuracy != null ? ` (${device.osAccuracy}%)` : ''}`
              : 'Undetected'}
          </dd>
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
        <h3 className="text-sm font-semibold mb-1 flex items-center gap-2">
          <span>Services ({services.length})</span>
          {services.some(s => s.protocolFamily === 'OT_ICS') && (
            <span
              data-testid="ot-detected-indicator"
              className="bg-amber-100 text-amber-800 rounded px-2 py-0.5 text-xs font-semibold"
            >
              OT/ICS protocols detected
            </span>
          )}
        </h3>
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
              {services.map(s => {
                const isOt = s.protocolFamily === 'OT_ICS';
                const vp = [s.vendor, s.product].filter(Boolean).join(' ');
                return (
                  <tr key={s.id}>
                    <td>{s.port}</td>
                    <td>
                      {s.protocol}
                      {isOt && (
                        <span
                          data-testid="ot-service-badge"
                          className="ml-1 bg-amber-100 text-amber-800 rounded px-1.5 py-0.5 text-[10px] font-semibold align-middle"
                        >
                          ICS / OT
                        </span>
                      )}
                    </td>
                    <td>
                      {(isOt ? s.name : (s.name ?? s.product)) ?? '—'}
                      {isOt && vp && <span className="block text-xs text-gray-500">{vp}</span>}
                    </td>
                    <td>{s.version ?? '—'}</td>
                  </tr>
                );
              })}
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
