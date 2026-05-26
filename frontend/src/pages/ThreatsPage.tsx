import { ThreatsDashboard } from '../components/ThreatsDashboard';

/**
 * Threats page — wraps the top-N at-risk leaderboard + CVE evidence drilldown.
 */
export function ThreatsPage() {
  return (
    <div className="h-full overflow-auto">
      <ThreatsDashboard />
    </div>
  );
}
