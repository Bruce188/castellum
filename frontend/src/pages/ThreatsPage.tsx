import { ThreatsDashboard } from '../components/ThreatsDashboard';
import { useAuth } from '../hooks/useAuth';

/**
 * Threats page — wraps the top-N at-risk leaderboard + CVE evidence drilldown.
 */
export function ThreatsPage() {
  const auth = useAuth();
  const isAdmin = auth.roles?.includes('ADMIN') ?? false;
  return (
    <div className="h-full overflow-auto">
      <ThreatsDashboard isAdmin={isAdmin} />
    </div>
  );
}
