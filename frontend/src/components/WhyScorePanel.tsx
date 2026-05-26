import type { DeviceRiskDto } from '../api/types';

interface Props {
  risk: DeviceRiskDto | null;
}

/**
 * "Why this score?" breakdown. Surfaces the composite-formula inputs so an operator
 * can read the score's provenance directly:
 *
 * <pre>
 *   composite = CVSS_max * (1 + EPSS_max) * (KEV ? 1.5 : 1) * (1 + criticalityWeight) / 2
 * </pre>
 *
 * Renders nothing when the risk DTO is absent or the backend has not supplied the
 * {@code components} field (legacy responses or empty CVE matches).
 */
export function WhyScorePanel({ risk }: Props) {
  if (!risk || !risk.components) return null;
  const c = risk.components;

  return (
    <section className="rounded border bg-gray-50 p-3 text-sm" data-testid="why-score-panel">
      <h3 className="font-semibold mb-2 text-gray-700">Why this score?</h3>
      <p className="text-xs text-gray-500 mb-2">
        composite = CVSS<sub>max</sub> × (1 + EPSS<sub>max</sub>) × (KEV ? 1.5 : 1) × (1 + criticality) / 2
      </p>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1">
        <dt className="text-gray-500">CVSS<sub>max</sub></dt>
        <dd className="font-mono">{c.cvssMax}</dd>

        <dt className="text-gray-500">EPSS<sub>max</sub></dt>
        <dd className="font-mono">{c.epssMax}</dd>

        <dt className="text-gray-500">KEV present</dt>
        <dd className={c.kevPresent ? 'font-mono text-red-700' : 'font-mono text-gray-700'}>
          {c.kevPresent ? 'yes' : 'no'}
        </dd>

        <dt className="text-gray-500">criticality weight</dt>
        <dd className="font-mono">{c.criticalityWeight}</dd>

        <dt className="border-t pt-1 text-gray-700 font-semibold">composite score</dt>
        <dd className="border-t pt-1 font-mono font-semibold">{risk.score}</dd>
      </dl>
    </section>
  );
}
