/**
 * CVEs page — placeholder until a fleet-wide CVE listing endpoint lands.
 *
 * Today the API exposes {@code GET /api/cve/{cveId}} for per-CVE detail and
 * {@code GET /api/risk/top} for the top-N at-risk leaderboard, but no paginated
 * fleet-wide CVE index. This page redirects readers to the Threats view + the
 * per-device CVE evidence panel until that endpoint is added.
 */
export function CvesPage() {
  return (
    <div className="h-full overflow-auto p-6">
      <h1 className="text-xl font-semibold text-gray-800 mb-2">CVEs</h1>
      <p className="text-sm text-gray-600 max-w-prose">
        Browse all CVEs — coming soon. In the meantime see the{' '}
        <span className="font-medium">Threats</span> page for the top-N at-risk
        leaderboard, or click into a device on{' '}
        <span className="font-medium">Topology</span> to see its CVE evidence.
      </p>
    </div>
  );
}
