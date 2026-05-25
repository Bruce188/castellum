import { DiscoveryControlPanel } from '../components/DiscoveryControlPanel';
import { OtProbePanel } from '../components/OtProbePanel';
import { useAuth } from '../hooks/useAuth';

/**
 * Settings — admin operations. Hosts the passive-discovery control panel and
 * the OT/ICS read-only fingerprint probe. Both panels enforce ADMIN-only writes
 * (the controls are disabled for VIEWERs; the backend enforces RBAC regardless).
 */
export function SettingsPage() {
  const auth = useAuth();
  const isAdmin = auth.roles?.includes('ADMIN') ?? false;
  return (
    <div className="h-full overflow-auto p-6">
      <h1 className="text-xl font-semibold text-gray-800 mb-4">Settings</h1>
      <DiscoveryControlPanel isAdmin={isAdmin} />
      <OtProbePanel isAdmin={isAdmin} />
    </div>
  );
}
