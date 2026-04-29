import type { RiskTier } from '../api/types';

export function toRiskTier(score: number | null | undefined): RiskTier {
  if (score === null || score === undefined || Number.isNaN(score)) return 'unknown';
  if (score < 4) return 'low';
  if (score < 7) return 'med';
  if (score < 9) return 'high';
  return 'crit';
}

export const tierColor: Record<RiskTier, string> = {
  low: '#16a34a',
  med: '#eab308',
  high: '#f97316',
  crit: '#dc2626',
  unknown: '#9ca3af',
};
