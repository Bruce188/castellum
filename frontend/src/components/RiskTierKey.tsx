/**
 * Non-interactive risk-tier key. Colors are sourced from `tierColor`
 * (single source of truth, AC#1) — never hardcoded here.
 */
import type { RiskTier } from '../api/types';
import { tierColor } from '../lib/riskTier';

const TIERS: ReadonlyArray<RiskTier> = ['low', 'med', 'high', 'crit', 'unknown'];

const TIER_LABEL: Record<RiskTier, string> = {
  low: 'Low',
  med: 'Medium',
  high: 'High',
  crit: 'Critical',
  unknown: 'Unknown',
};

export function RiskTierKey() {
  return (
    <ul data-testid="risk-tier-key" className="text-xs space-y-1">
      {TIERS.map(t => (
        <li key={t} className="flex items-center gap-2">
          <span
            data-testid={`tier-swatch-${t}`}
            className="inline-block w-3 h-3 rounded-sm"
            style={{ backgroundColor: tierColor[t] }}
            aria-hidden="true"
          />
          <span>{TIER_LABEL[t]}</span>
        </li>
      ))}
    </ul>
  );
}
