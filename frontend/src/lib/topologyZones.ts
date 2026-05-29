/**
 * Zone-grouping definitions for the topology compound-node layout.
 *
 * Every {@link DiscoveryScope} value maps to a zone id. Zones are displayed
 * as cytoscape compound (parent) nodes with a labeled background so the
 * operator can immediately see which network boundary each host belongs to.
 *
 * Mapping rationale:
 *   HOME         → zone-home    (LAN / Home network)
 *   DOCKER_BRIDGE→ zone-docker  (Container / Docker bridge)
 *   LINK_LOCAL   → zone-local   (Link-local / APIPA — grouped with LOOPBACK as "Local")
 *   LOOPBACK     → zone-local   (Loopback — same "Local" zone as LINK_LOCAL)
 *   PUBLIC       → zone-public  (External / Public internet)
 *
 * LINK_LOCAL and LOOPBACK are intentionally grouped into a single "Local"
 * zone: both represent non-routable, host-local scopes that have no
 * meaningful network-boundary distinction from the operator's perspective.
 */

import type { DiscoveryScope } from '../api/types';

// ─── Zone IDs ───────────────────────────────────────────────────────────────

export type ZoneId = 'zone-home' | 'zone-docker' | 'zone-local' | 'zone-public';

// ─── Scope → Zone mapping ───────────────────────────────────────────────────

const SCOPE_TO_ZONE: Record<DiscoveryScope, ZoneId> = {
  HOME:          'zone-home',
  DOCKER_BRIDGE: 'zone-docker',
  LINK_LOCAL:    'zone-local',
  LOOPBACK:      'zone-local',
  PUBLIC:        'zone-public',
};

/** Return the zone id for a given {@link DiscoveryScope}. */
export function scopeToZoneId(scope: DiscoveryScope): ZoneId {
  return SCOPE_TO_ZONE[scope];
}

// ─── Zone definitions (label + member scopes) ───────────────────────────────

export interface ZoneDefinition {
  /** Human-readable label rendered inside the compound parent node. */
  label: string;
  /** All DiscoveryScope values that belong to this zone. */
  scopes: ReadonlyArray<DiscoveryScope>;
}

export const ZONE_DEFINITIONS: Record<ZoneId, ZoneDefinition> = {
  'zone-home':   { label: 'Home / LAN',      scopes: ['HOME'] },
  'zone-docker': { label: 'Docker',           scopes: ['DOCKER_BRIDGE'] },
  'zone-local':  { label: 'Local',            scopes: ['LINK_LOCAL', 'LOOPBACK'] },
  'zone-public': { label: 'External / Public', scopes: ['PUBLIC'] },
};

// ─── Zone colors (background fill for compound parent nodes) ────────────────

/**
 * Background color for each zone compound node.
 * Uses semi-transparent fills so child node labels stay readable.
 */
export const ZONE_COLORS: Record<ZoneId, string> = {
  'zone-home':   '#dbeafe', // light blue
  'zone-docker': '#dcfce7', // light green
  'zone-local':  '#f3f4f6', // light grey
  'zone-public': '#fee2e2', // light red/orange
};

/**
 * Border color for each zone compound node (slightly darker than the fill).
 */
export const ZONE_BORDER_COLORS: Record<ZoneId, string> = {
  'zone-home':   '#93c5fd',
  'zone-docker': '#86efac',
  'zone-local':  '#d1d5db',
  'zone-public': '#fca5a5',
};

/** Text color for zone compound node labels. */
export const ZONE_LABEL_COLORS: Record<ZoneId, string> = {
  'zone-home':   '#1e40af',
  'zone-docker': '#166534',
  'zone-local':  '#4b5563',
  'zone-public': '#991b1b',
};

// ─── Ordered list of all zone ids (display order in legend) ─────────────────

export const ZONE_ORDER: ReadonlyArray<ZoneId> = [
  'zone-home',
  'zone-docker',
  'zone-local',
  'zone-public',
];

/**
 * Given a set of present {@link DiscoveryScope} values, return the ordered
 * list of zone ids that have at least one member. Empty zones are excluded.
 */
export function presentZoneIds(scopes: Iterable<DiscoveryScope>): ZoneId[] {
  const present = new Set<ZoneId>();
  for (const s of scopes) {
    present.add(SCOPE_TO_ZONE[s]);
  }
  return ZONE_ORDER.filter(z => present.has(z));
}
