// CVSS v3.1 base-vector decode — local static-map parser (no third-party lib).
// Label-decodes the 8 base metrics only (AV, AC, PR, UI, S, C, I, A). No
// temporal/environmental metrics, and no scoring-formula recomputation.

export interface CvssMetric {
  key: string;
  label: string;
  value: string;
  valueLabel: string;
}

export interface DecodedCvss {
  metrics: CvssMetric[];
}

export type SeverityBand = 'None' | 'Low' | 'Medium' | 'High' | 'Critical';

interface MetricDef {
  key: string;
  label: string;
  values: Record<string, string>;
}

// Fixed output order: AV, AC, PR, UI, S, C, I, A.
const IMPACT: Record<string, string> = { N: 'None', L: 'Low', H: 'High' };

const BASE_METRICS: MetricDef[] = [
  { key: 'AV', label: 'Attack Vector', values: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' } },
  { key: 'AC', label: 'Attack Complexity', values: { L: 'Low', H: 'High' } },
  { key: 'PR', label: 'Privileges Required', values: { N: 'None', L: 'Low', H: 'High' } },
  { key: 'UI', label: 'User Interaction', values: { N: 'None', R: 'Required' } },
  { key: 'S', label: 'Scope', values: { U: 'Unchanged', C: 'Changed' } },
  { key: 'C', label: 'Confidentiality', values: IMPACT },
  { key: 'I', label: 'Integrity', values: IMPACT },
  { key: 'A', label: 'Availability', values: IMPACT },
];

const PREFIX = 'CVSS:3.1/';

export function parseCvssV31Vector(vector: string | null | undefined): DecodedCvss | null {
  if (!vector || !vector.startsWith(PREFIX)) return null;

  const tokens = vector.slice(PREFIX.length).split('/');
  const provided = new Map<string, string>();
  for (const token of tokens) {
    const [key, value] = token.split(':');
    if (!key || value === undefined) return null;
    provided.set(key, value);
  }

  const metrics: CvssMetric[] = [];
  for (const def of BASE_METRICS) {
    const value = provided.get(def.key);
    if (value === undefined) return null;
    const valueLabel = def.values[value];
    if (valueLabel === undefined) return null;
    metrics.push({ key: def.key, label: def.label, value, valueLabel });
  }

  return { metrics };
}

export function severityBand(score: number | string | null | undefined): SeverityBand | null {
  if (score === null || score === undefined || score === '') return null;
  const n = Number(score);
  if (!Number.isFinite(n)) return null;
  if (n <= 0) return 'None';
  if (n < 4.0) return 'Low';
  if (n < 7.0) return 'Medium';
  if (n < 9.0) return 'High';
  return 'Critical';
}
