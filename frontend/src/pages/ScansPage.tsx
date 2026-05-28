import { UnifiedScanControl } from '../components/UnifiedScanControl';
import { RecentScansPanel } from '../components/RecentScansPanel';
import { useAuth } from '../hooks/useAuth';

/**
 * Scans page — unified "Scan this network" control as the primary action,
 * with per-type advanced controls preserved under the unified-advanced-toggle.
 */
export function ScansPage() {
  const { roles } = useAuth();
  const isAdmin = roles.includes('ADMIN');
  return (
    <div className="flex flex-col h-full overflow-auto">
      <UnifiedScanControl isAdmin={isAdmin} />
      <RecentScansPanel />
    </div>
  );
}
