import { useCallback, useEffect, useState } from 'react';
import { TopologyView } from '../components/TopologyView';
import { TopologyLegend } from '../components/TopologyLegend';
import { DeviceDetailPanel } from '../components/DeviceDetailPanel';
import { EmptyCorpusBanner } from '../components/EmptyCorpusBanner';
import { OnboardingCard } from '../components/OnboardingCard';
import { ScanTriggerForm } from '../components/ScanTriggerForm';
import { OtProbePanel } from '../components/OtProbePanel';
import { api } from '../api/client';
import { useAuth } from '../hooks/useAuth';
import type { Device, DeviceRiskDto, DiscoveryScope, NetworkService } from '../api/types';

const SCOPE_STORAGE_KEY = 'castellum.topology.scope-visibility';
const DEFAULT_VISIBILITY: Record<DiscoveryScope, boolean> = {
  HOME: true,
  DOCKER_BRIDGE: true,
  LINK_LOCAL: true,
  LOOPBACK: true,
  PUBLIC: true,
};

function loadVisibility(): Record<DiscoveryScope, boolean> {
  try {
    const raw = localStorage.getItem(SCOPE_STORAGE_KEY);
    if (!raw) return DEFAULT_VISIBILITY;
    const parsed = JSON.parse(raw);
    return { ...DEFAULT_VISIBILITY, ...parsed };
  } catch {
    return DEFAULT_VISIBILITY;
  }
}

/**
 * Topology landing page — replaces the all-in-one shell from the pre-router build.
 *
 * Owns the device / risk / selected-device state that {@link TopologyView} and
 * {@link DeviceDetailPanel} need, plus the in-page {@link ScanTriggerForm} that
 * lets the operator kick off a scan without leaving the dashboard. Also tracks
 * scan count on mount so {@link OnboardingCard} only renders for first-time users.
 */
export function TopologyPage() {
  const auth = useAuth();
  const [devices, setDevices] = useState<Device[]>([]);
  const [risksById, setRisksById] = useState<Map<number, DeviceRiskDto>>(new Map());
  const [risksLoading, setRisksLoading] = useState<boolean>(false);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [selectedRisk, setSelectedRisk] = useState<DeviceRiskDto | null>(null);
  const [selectedServices, setSelectedServices] = useState<NetworkService[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [scanCount, setScanCount] = useState<number | null>(null);
  const [scopeVisibility, setScopeVisibility] = useState<Record<DiscoveryScope, boolean>>(() => loadVisibility());

  // Single source of truth for the device-and-risk fanout. Used by both the
  // mount-effect below and the `onDeviceMutated` callback passed into
  // <DeviceDetailPanel> so inline-edit / decommission can refresh the graph.
  //
  // Historical note: there used to be two near-duplicate effects here (one
  // wired through refetchDevices, one inlined) — they doubled the request
  // count on mount and contributed to the "Failed to fetch" pill during the
  // initial-sync window. Collapsed to a single mount effect.
  const refetchDevices = useCallback(async () => {
    if (!auth.token) return;
    setRisksLoading(true);
    try {
      const page = await api.listDevices();
      setDevices(page.content);
      const map = await api.deviceRisksBatch(page.content.map(d => d.id));
      setRisksById(map);
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'load failed');
    } finally {
      setRisksLoading(false);
    }
  }, [auth.token]);

  useEffect(() => {
    if (!auth.token) return;
    let cancelled = false;
    const run = async () => {
      if (cancelled) return;
      setRisksLoading(true);
      try {
        const page = await api.listDevices();
        if (cancelled) return;
        setDevices(page.content);
        const map = await api.deviceRisksBatch(page.content.map(d => d.id));
        if (cancelled) return;
        setRisksById(map);
        setLoadError(null);
      } catch (err) {
        if (cancelled) return;
        setLoadError(err instanceof Error ? err.message : 'load failed');
      } finally {
        if (!cancelled) setRisksLoading(false);
      }
    };
    void run();
    return () => { cancelled = true; };
  }, [auth.token]);

  // Track scan count so the onboarding card can self-dismiss.
  useEffect(() => {
    if (!auth.token) return;
    let cancelled = false;
    (async () => {
      try {
        const page = await api.listScans(1);
        if (!cancelled) setScanCount(page.totalElements);
      } catch {
        if (!cancelled) setScanCount(0);
      }
    })();
    return () => { cancelled = true; };
  }, [auth.token]);

  async function handleNodeClick(id: number) {
    const dev = devices.find(d => d.id === id) ?? null;
    setSelectedDevice(dev);
    if (dev === null) return;
    try {
      const [services, risk] = await Promise.all([
        api.listServicesForDevice(id),
        api.deviceRisk(id),
      ]);
      setSelectedServices(services);
      setSelectedRisk(risk);
    } catch {
      setSelectedServices([]);
      setSelectedRisk(null);
    }
  }

  function handleBackgroundClick() {
    setSelectedDevice(null);
    setSelectedRisk(null);
    setSelectedServices([]);
  }

  const isAdmin = auth.roles?.includes('ADMIN') ?? false;

  return (
    <div className="grid grid-rows-[auto_1fr] h-full">
      {/* Banner + scan controls share ONE auto-sized row so <main> always lands
          in the 1fr track. Previously each was its own grid child against
          grid-rows-[auto_auto_1fr]; when EmptyCorpusBanner returns null (feeds
          populated) only two items remained, so <main> fell into an auto track
          that collapsed to 0 height and the Cytoscape canvas rendered blank. */}
      <div>
        <EmptyCorpusBanner isAdmin={isAdmin} />
        <header className="flex items-center justify-between gap-4">
          <ScanTriggerForm />
        </header>
        <details className="mt-2">
          <summary className="text-sm text-gray-600 cursor-pointer select-none">
            OT/ICS fingerprint probe
          </summary>
          <div className="mt-2">
            <OtProbePanel isAdmin={isAdmin} />
          </div>
        </details>
      </div>
      <main className="relative">
        <TopologyView
          devices={devices}
          risksById={risksById}
          risksLoading={risksLoading}
          onNodeClick={handleNodeClick}
          onBackgroundClick={handleBackgroundClick}
          scopeVisibility={scopeVisibility}
        />
        <TopologyLegend
          visibility={scopeVisibility}
          onChange={next => {
            setScopeVisibility(next);
            try { localStorage.setItem(SCOPE_STORAGE_KEY, JSON.stringify(next)); } catch { /* quota / SSR — drop silently */ }
          }}
          presentScopes={new Set(devices.filter(d => scopeVisibility[d.discoveryScope] ?? true).map(d => d.discoveryScope))}
        />
        <DeviceDetailPanel
          device={selectedDevice}
          risk={selectedRisk}
          services={selectedServices}
          onClose={handleBackgroundClick}
          isAdmin={isAdmin}
          onDeviceMutated={refetchDevices}
        />
        {scanCount !== null && <OnboardingCard scanCount={scanCount} />}
        {devices.length === 0 && !loadError && (
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <p className="text-gray-500 text-center max-w-md pointer-events-auto">
              No devices yet. Submit a scan above or POST <code>/api/devices</code> to populate the graph.
            </p>
          </div>
        )}
        {loadError && (
          <div className="absolute inset-0 flex items-center justify-center">
            <p className="text-red-600">Failed to load: {loadError}</p>
          </div>
        )}
      </main>
    </div>
  );
}
