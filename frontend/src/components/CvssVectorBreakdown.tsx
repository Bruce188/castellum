import { parseCvssV31Vector, severityBand } from '../lib/cvss';

interface Props {
  vector: string | null | undefined;
  score?: string | null;
}

// Presentational decode of a CVSS v3.1 base vector. Renders the human-readable
// metric/value-label grid alongside the raw vector string, plus a severity band
// label when a numeric score is supplied. Degrades gracefully: a malformed
// vector falls back to the raw string, and an absent vector renders an em-dash.
export function CvssVectorBreakdown({ vector, score }: Props) {
  const decoded = parseCvssV31Vector(vector);
  const band = severityBand(score);

  if (!decoded) {
    return (
      <div className="text-xs font-mono text-gray-500 break-all">
        {vector && vector.length > 0 ? vector : '—'}
      </div>
    );
  }

  return (
    <div className="text-xs">
      {band && (
        <span
          data-testid="cvss-severity-band"
          className="inline-block mb-2 rounded px-2 py-0.5 bg-gray-100 text-gray-800 font-semibold"
        >
          Severity: {band}
        </span>
      )}
      <dl className="grid grid-cols-[max-content_1fr] gap-x-2 gap-y-0.5">
        {decoded.metrics.map((m) => (
          <div key={m.key} className="contents">
            <dt className="text-gray-500">{m.label}</dt>
            <dd className="text-gray-800 font-medium">{m.valueLabel}</dd>
          </div>
        ))}
      </dl>
      <div data-testid="cvss-raw-vector" className="mt-2 text-gray-400">
        <span className="text-xs mr-1">Raw vector</span>
        <span className="font-mono text-xs break-all">{vector}</span>
      </div>
    </div>
  );
}
