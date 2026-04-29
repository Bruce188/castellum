import { useEffect, useState } from 'react';
import { ScanTriggerForm } from './components/ScanTriggerForm';
import { TopologyView } from './components/TopologyView';
import { DeviceDetailPanel } from './components/DeviceDetailPanel';
import { api } from './api/client';
import type { Device, DeviceRiskDto, NetworkService } from './api/types';
import './index.css';

function App() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [risksById, setRisksById] = useState<Map<number, DeviceRiskDto>>(new Map());
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [selectedRisk, setSelectedRisk] = useState<DeviceRiskDto | null>(null);
  const [selectedServices, setSelectedServices] = useState<NetworkService[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
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
        if (!cancelled) setLoadError(err instanceof Error ? err.message : 'load failed');
      }
    })();
    return () => { cancelled = true; };
  }, []);

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
    <div className="grid grid-rows-[auto_1fr] h-screen">
      <header><ScanTriggerForm /></header>
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
        />
        {devices.length === 0 && !loadError && (
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <p className="text-gray-500 text-center max-w-md">
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

export default App;
