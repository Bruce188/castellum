import type { DiscoveryScope } from '../api/types';
import { scopeBorderColor } from '../lib/scopeColors';

interface Props {
  visibility: Record<DiscoveryScope, boolean>;
  onChange: (next: Record<DiscoveryScope, boolean>) => void;
}

const SCOPES: ReadonlyArray<DiscoveryScope> = [
  'HOME',
  'DOCKER_BRIDGE',
  'LINK_LOCAL',
  'LOOPBACK',
  'PUBLIC',
];

/**
 * Topology canvas overlay (top-right) — five checkbox rows, one per
 * {@link DiscoveryScope}. Pure presentational: the parent owns the
 * visibility state (and the {@code localStorage} persistence).
 */
export function TopologyLegend({ visibility, onChange }: Props) {
  return (
    <ul
      data-testid="topology-legend"
      className="absolute top-2 right-2 bg-white border border-gray-200 rounded shadow-sm p-2 text-xs space-y-1 z-10"
    >
      {SCOPES.map(scope => (
        <li key={scope} className="flex items-center gap-2">
          <span
            className="inline-block w-3 h-3 rounded-sm"
            style={{ backgroundColor: scopeBorderColor[scope] }}
            aria-hidden="true"
          />
          <label className="flex items-center gap-1 cursor-pointer">
            <input
              type="checkbox"
              aria-label={scope}
              checked={visibility[scope]}
              onChange={e => onChange({ ...visibility, [scope]: e.target.checked })}
            />
            <span>{scope}</span>
          </label>
        </li>
      ))}
    </ul>
  );
}
