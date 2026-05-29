import type { DiscoveryScope } from '../api/types';
import { scopeBorderColor } from '../lib/scopeColors';
import { RiskTierKey } from './RiskTierKey';
import {
  presentZoneIds,
  ZONE_DEFINITIONS,
  ZONE_COLORS,
  ZONE_BORDER_COLORS,
} from '../lib/topologyZones';

interface Props {
  visibility: Record<DiscoveryScope, boolean>;
  onChange: (next: Record<DiscoveryScope, boolean>) => void;
  /**
   * Set of DiscoveryScope values actually present in the current device list.
   * The legend uses this to show only the zone rows for zones that have members.
   * When omitted (e.g. during initial render), no zone rows are shown.
   */
  presentScopes?: Set<DiscoveryScope>;
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
 * {@link DiscoveryScope}, plus a non-interactive risk-tier key section.
 * Pure presentational: the parent owns the visibility state (and the
 * {@code localStorage} persistence).
 */
export function TopologyLegend({ visibility, onChange, presentScopes }: Props) {
  // Compute present zone ids (in display order) from the presentScopes set.
  const zoneIds = presentScopes ? presentZoneIds(presentScopes) : [];

  return (
    <div
      data-testid="topology-legend"
      className="absolute top-2 right-2 bg-white border border-gray-200 rounded shadow-sm p-2 text-xs space-y-1 z-10"
    >
      <ul className="space-y-1">
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
      {zoneIds.length > 0 && (
        <>
          <hr className="my-1 border-gray-100" />
          <div data-testid="topology-legend-zones" className="space-y-1">
            <p className="font-semibold text-gray-500 uppercase tracking-wide" style={{ fontSize: 9 }}>Zones</p>
            {zoneIds.map(zid => (
              <div
                key={zid}
                data-testid={`zone-legend-row-${zid}`}
                className="flex items-center gap-2"
              >
                <span
                  className="inline-block w-3 h-3 rounded-sm border"
                  style={{
                    backgroundColor: ZONE_COLORS[zid],
                    borderColor: ZONE_BORDER_COLORS[zid],
                  }}
                  aria-hidden="true"
                />
                <span>{ZONE_DEFINITIONS[zid].label}</span>
              </div>
            ))}
          </div>
        </>
      )}
      <hr className="my-1 border-gray-100" />
      <RiskTierKey />
    </div>
  );
}
