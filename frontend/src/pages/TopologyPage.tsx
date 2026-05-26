import { useCallback, useEffect, useState } from 'react';
import { TopologyView } from '../components/TopologyView';
import { DeviceDetailPanel } from '../components/DeviceDetailPanel';
import { OnboardingCard } from '../components/OnboardingCard';
import { ScanTriggerForm } from '../components/ScanTriggerForm';
import { api } from '../api/client';
import { useAuth } from '../hooks/useAuth';
import type { Device, DeviceRiskDto, NetworkService } from '../api/types';

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
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [selectedRisk, setSelectedRisk] = useState<DeviceRiskDto | null>(null);
  const [selectedServices, setSelectedServices] = useState<NetworkService[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [scanCount, setScanCount] = useState<number | null>(null);

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
    try {
      const page = await api.listDevices();
      setDevices(page.content);
      const results = await Promise.allSettled(
        page.content.map(d => api.deviceRisk(d.id))
      );
      const map = new Map<number, DeviceRiskDto>();
      results.forEach((r, i) => {
        if (r.status === 'fulfilled') map.set(page.content[i].id, r.value);
      });
      setRisksById(map);
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'load failed');
    }
  }, [auth.token]);

  useEffect(() => {
    if (!auth.token) return;
    void refetchDevices();
  }, [auth.token, refetchDevices]);

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

  return (
    <div className="grid grid-rows-[auto_1fr] h-full">
      <header className="flex items-center justify-between gap-4">
        <ScanTriggerForm />
      </header>
      <main className="relative">
        <TopologyView
          devices={devices}
          risksById={risksById}
          onNodeClick={handleNodeClick}
          onBackgroundClick={handleBackgroundClick}
        />
        <DeviceDetailPanel
          device={selectedDevice}
          risk={selectedRisk}
          services={selectedServices}
          onClose={handleBackgroundClick}
          isAdmin={auth.roles?.includes('ADMIN') ?? false}
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
