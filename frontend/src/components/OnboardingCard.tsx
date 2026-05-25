interface Props {
  scanCount: number;
}

/**
 * First-time onboarding card surfaced on the Topology page.
 *
 * Visible while {@code scanCount === 0} — i.e. the operator has not yet triggered
 * any scan. Walks through the three steps required before the dashboard becomes
 * meaningful: (1) sync threat-intel feeds, (2) run a scan, (3) tag device criticality.
 * Returns {@code null} once any scan exists so the card auto-dismisses without
 * needing an explicit close button.
 */
export function OnboardingCard({ scanCount }: Props) {
  if (scanCount > 0) return null;

  return (
    <aside
      data-testid="onboarding-card"
      aria-label="Get started"
      className="absolute top-4 right-4 z-10 w-80 bg-white border border-blue-200 rounded-lg shadow-lg p-4"
    >
      <h2 className="text-sm font-semibold text-blue-900 mb-2">Get started</h2>
      <ol className="space-y-2 text-sm text-gray-700">
        <li className="flex items-start gap-2">
          <span className="shrink-0 w-5 h-5 rounded-full bg-blue-600 text-white text-xs font-bold flex items-center justify-center">
            1
          </span>
          <span>Sync threat-intel feeds (banner above when empty).</span>
        </li>
        <li className="flex items-start gap-2">
          <span className="shrink-0 w-5 h-5 rounded-full bg-blue-600 text-white text-xs font-bold flex items-center justify-center">
            2
          </span>
          <span>Run a scan from the Scans page or the form above.</span>
        </li>
        <li className="flex items-start gap-2">
          <span className="shrink-0 w-5 h-5 rounded-full bg-blue-600 text-white text-xs font-bold flex items-center justify-center">
            3
          </span>
          <span>Set device criticality once devices appear in the topology.</span>
        </li>
      </ol>
    </aside>
  );
}
