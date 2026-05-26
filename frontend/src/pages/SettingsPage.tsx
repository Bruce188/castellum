import { ChangePasswordForm } from '../components/ChangePasswordForm';
import { DiscoveryControlPanel } from '../components/DiscoveryControlPanel';
import { OtProbePanel } from '../components/OtProbePanel';
import { UserManagementPanel } from '../components/UserManagementPanel';
import { useAuth } from '../hooks/useAuth';

/**
 * Settings — admin operations.
 *
 * <ul>
 *   <li>Change-my-password form (every authenticated user)</li>
 *   <li>User management (ADMIN-gated; backend enforces RBAC regardless)</li>
 *   <li>Passive-discovery control panel (ADMIN-gated)</li>
 *   <li>OT/ICS read-only fingerprint probe (ADMIN-gated)</li>
 * </ul>
 */
export function SettingsPage() {
  const auth = useAuth();
  const isAdmin = auth.roles?.includes('ADMIN') ?? false;
  return (
    <div className="h-full overflow-auto p-6">
      <h1 className="text-xl font-semibold text-gray-800 mb-4">Settings</h1>
      <ChangePasswordForm />
      <UserManagementPanel isAdmin={isAdmin} />
      <DiscoveryControlPanel isAdmin={isAdmin} />
      <OtProbePanel isAdmin={isAdmin} />
    </div>
  );
}
