import type { Device } from '../api/types';
import { scopeToZoneId } from './topologyZones';
import { ipv4Slash24 } from './subnetEdges';
import { isDockerNetGateway } from './dockerNetworkGroups';

/**
 * Edge produced by {@link buildGatewayEdges}. Structurally identical kinds
 * coexist so Cytoscape can style them via {@code edge[kind = ...]} selectors:
 *
 * <ul>
 *   <li>{@code gateway} — peer → gateway-of-/24 (solid stroke).</li>
 *   <li>{@code docker-bridge} — docker-host → DOCKER_BRIDGE device (dashed).</li>
 *   <li>{@code isolated} — self-anchored marker for a lone link-local/APIPA
 *       node so it is not silently dropped (source === target === id).</li>
 * </ul>
 *
 * {@code gatewayIp} is informational metadata for the {@code gateway} kind; it
 * is intentionally undefined on {@code docker-bridge} edges because the source
 * is identified by the IP-based docker-host heuristic, not by being the lowest
 * IP of a /24.
 */
export interface GatewayEdge {
  data: {
    id: string;
    source: string;
    target: string;
    kind: 'gateway' | 'docker-bridge' | 'isolated';
    gatewayIp?: string;
    /** True when the source and target devices belong to different topology zones. */
    crossZone?: boolean;
  };
}

/**
 * Docker-host detection key. The bound IP defaults to the Castellum reference
 * environment's docker host (192.168.68.51); an operator with a non-default
 * setup can override at runtime via {@code localStorage.setItem(...)}.
 */
const DOCKER_HOST_IP_LS_KEY = 'castellum.topology.docker-host-ip';
const DEFAULT_DOCKER_HOST_IP = '192.168.68.51';

function lastOctet(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const n = Number(parts[3]);
  return Number.isInteger(n) ? n : null;
}

function ipToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let v = 0;
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    v = v * 256 + n;
  }
  return v;
}

/**
 * Pick the gateway device for a /24 group:
 * <ol>
 *   <li>Device whose IP ends in {@code .1} (most common home/SOHO router).</li>
 *   <li>Otherwise the lowest IP in the group.</li>
 *   <li>Tie-break (defensive): lowest device {@code id}.</li>
 * </ol>
 */
function pickGateway(group: Device[]): Device {
  const dot1 = group.find(d => lastOctet(d.ipAddress) === 1);
  if (dot1) return dot1;
  const sorted = [...group].sort((a, b) => {
    const ai = ipToInt(a.ipAddress);
    const bi = ipToInt(b.ipAddress);
    if (ai !== null && bi !== null && ai !== bi) return ai - bi;
    return a.id - b.id;
  });
  return sorted[0];
}

/**
 * Identify the device that hosts Castellum's docker bridge for the `"local"` origin.
 *
 * Detection is IP-based only: a HOME-scope device whose IP matches
 * {@code localStorage[castellum.topology.docker-host-ip]} (default {@code 192.168.68.51}).
 *
 * Hostname matching on {@code "host.docker.internal"} was removed — that string is a Docker
 * bridge-gateway alias and is never stored as a real device hostname by the backend
 * (filtered by {@code DeviceUpsertService}). IP is the stable, unambiguous identity.
 *
 * Returns {@code null} if no candidate exists, in which case
 * DOCKER_BRIDGE devices remain orphans (no synthetic edges).
 *
 * Retained as the {@code "local"}/no-origin fallback for {@link findDockerHosts}.
 */
function findDockerHost(devices: Device[]): Device | null {
  const override = (typeof localStorage !== 'undefined'
    ? localStorage.getItem(DOCKER_HOST_IP_LS_KEY)
    : null) ?? DEFAULT_DOCKER_HOST_IP;
  for (const d of devices) {
    if (d.discoveryScope !== 'HOME') continue;
    if (d.ipAddress === override) return d;
  }
  return null;
}

/**
 * Build a map of {@code originHostIp → pivot HOME device} for all distinct origins
 * among DOCKER_BRIDGE devices.
 *
 * Resolution per origin:
 * - {@code "local"} → the existing localStorage/DEFAULT_DOCKER_HOST_IP match via
 *   {@link findDockerHost} (retained as the local/no-origin fallback).
 * - non-local origin → the HOME device whose {@code ipAddress} equals the origin host IP
 *   (min by id when multiple qualify).
 *
 * Origins with no matching HOME device are omitted from the map — their DOCKER_BRIDGE
 * members become orphans (no crash, no edges).
 */
function findDockerHosts(devices: Device[]): Map<string, Device> {
  const pivotByOrigin = new Map<string, Device>();

  // Collect distinct DOCKER_BRIDGE origins.
  const origins = new Set<string>();
  for (const d of devices) {
    if (d.discoveryScope !== 'DOCKER_BRIDGE') continue;
    origins.add(d.originHostIp);
  }

  // Build HOME-by-IP lookup for non-local resolution.
  const homeByIp = new Map<string, Device[]>();
  for (const d of devices) {
    if (d.discoveryScope !== 'HOME') continue;
    const list = homeByIp.get(d.ipAddress) ?? [];
    list.push(d);
    homeByIp.set(d.ipAddress, list);
  }

  for (const origin of origins) {
    if (origin === 'local') {
      // Retain localStorage override as the local fallback.
      const pivot = findDockerHost(devices);
      if (pivot !== null) pivotByOrigin.set('local', pivot);
    } else {
      // Non-local: HOME device whose IP matches the origin host IP, min-by-id.
      const candidates = homeByIp.get(origin) ?? [];
      if (candidates.length > 0) {
        const pivot = candidates.reduce((a, b) => (a.id <= b.id ? a : b));
        pivotByOrigin.set(origin, pivot);
      }
      // No match → origin omitted; its docker members become orphans.
    }
  }

  return pivotByOrigin;
}

/**
 * Build gateway-hub edges that replace the previous flat-star same-subnet
 * topology. Algorithm per docs/plan-v36.md § Task 3.2:
 * <ol>
 *   <li>Group devices by /24 (reuses {@link ipv4Slash24}).</li>
 *   <li>For each group with {@code >= 2} devices, pick a gateway and emit
 *       one edge per non-gateway peer → gateway with
 *       {@code kind: 'gateway'}. DOCKER_BRIDGE /24s with no docker-net
 *       gateway (unattached) are excluded from this step entirely.</li>
 *   <li>Singleton groups that are NOT rescued by the docker-bridge path emit
 *       a self-anchored {@code kind: 'isolated'} edge (source === target ===
 *       device id) so lone nodes (e.g. APIPA/LINK_LOCAL) carry an explicit
 *       unrouted affordance rather than floating with no context.</li>
 *   <li>If a docker host can be identified AND any DOCKER_BRIDGE device exists,
 *       emit synthetic docker-bridge edges per the AC3 routing rules.</li>
 * </ol>
 */
export function buildGatewayEdges(devices: Device[]): GatewayEdge[] {
  if (devices.length === 0) return [];

  const edges: GatewayEdge[] = [];

  // Build a lookup from device id → device for cross-zone annotation.
  const deviceById = new Map<number, Device>(devices.map(d => [d.id, d]));

  // Build per-origin pivot map — replaces single dockerHost for multi-origin support.
  // The local origin retains the localStorage/DEFAULT_DOCKER_HOST_IP fallback.
  const pivotByOrigin = findDockerHosts(devices);

  // Pre-compute /24 → docker-net gateway map.  This is needed both in Step 3
  // (docker-bridge routing) and in Step 1+2 (to exclude unattached DOCKER_BRIDGE
  // /24s from the general gateway-kind edge generation).
  const slash24ToDockerGateway = new Map<string, Device>();
  for (const d of devices) {
    if (!isDockerNetGateway(d)) continue;
    const slash24 = ipv4Slash24(d.ipAddress);
    if (slash24 !== null && !slash24ToDockerGateway.has(slash24)) {
      slash24ToDockerGateway.set(slash24, d);
    }
  }

  // A /24 is "unattached-docker" when ALL devices in it are DOCKER_BRIDGE but
  // none is a docker-net gateway.  Peers in such a /24 must not receive
  // gateway-kind edges between them (Change 2).
  function isUnattachedDockerSlash24(slash24: string, group: Device[]): boolean {
    if (slash24ToDockerGateway.has(slash24)) return false; // has a gateway → normal
    return group.every(d => d.discoveryScope === 'DOCKER_BRIDGE');
  }

  // Step 1+2: gateway edges per /24.
  const groups = new Map<string, Device[]>();
  for (const d of devices) {
    const key = ipv4Slash24(d.ipAddress);
    if (key === null) continue;
    const list = groups.get(key) ?? [];
    list.push(d);
    groups.set(key, list);
  }
  for (const [slash24, group] of groups.entries()) {
    // Change 2: skip entire /24 for gateway-kind edges when it is an unattached
    // docker /24 (all DOCKER_BRIDGE, no docker-net gateway).  These nodes render
    // as muted/disconnected; they get zero edges from the gateway-kind step.
    if (isUnattachedDockerSlash24(slash24, group)) continue;

    if (group.length < 2) {
      // Singleton /24 group: emit an isolated self-anchor unless the device is
      // a DOCKER_BRIDGE device that will be rescued by the docker-bridge path
      // (i.e. a docker host exists and will emit a db- edge for it).
      const lone = group[0];
      // Rescued if its origin has a pivot (per-origin check replaces single dockerHost guard).
      const rescuedByDockerBridge = lone.discoveryScope === 'DOCKER_BRIDGE' &&
        pivotByOrigin.has(lone.originHostIp);
      if (!rescuedByDockerBridge) {
        edges.push({
          data: {
            id: `iso-${lone.id}`,
            source: String(lone.id),
            target: String(lone.id),
            kind: 'isolated',
          },
        });
      }
      continue;
    }
    const gateway = pickGateway(group);
    for (const peer of group) {
      if (peer.id === gateway.id) continue;
      const crossZone = scopeToZoneId(peer.discoveryScope) !== scopeToZoneId(gateway.discoveryScope);
      edges.push({
        data: {
          id: `g-${peer.id}-${gateway.id}`,
          source: String(peer.id),
          target: String(gateway.id),
          kind: 'gateway',
          gatewayIp: gateway.ipAddress,
          ...(crossZone ? { crossZone: true } : {}),
        },
      });
    }
  }

  // Step 3: docker-bridge synthetic edges.
  //
  // Routing rules (per AC3), now per-origin:
  //   For each DOCKER_BRIDGE device, resolve its pivot via originHostIp from pivotByOrigin.
  //   a) docker-net gateway devices (isDockerNetGateway) → its origin's pivot
  //   b) published-port containers (publishesHostPort === true) → pivot directly
  //      AND (Change 1) also → their docker-net gateway when one exists for the /24
  //   c) internal-only containers (DOCKER_BRIDGE, not a gateway, publishesHostPort !== true)
  //      → edge from the container to its network's docker-net gateway (when one exists).
  //      If no gateway exists (unattached), emit NO edge (Change 2).
  //   If a device's origin has no resolved pivot, it becomes an orphan (no crash).
  for (const d of devices) {
    if (d.discoveryScope !== 'DOCKER_BRIDGE') continue;

    // Resolve the pivot for this device's origin.
    const pivot = pivotByOrigin.get(d.originHostIp) ?? null;
    if (pivot === null) continue; // no pivot for this origin → orphan

    const pivotDevice = deviceById.get(pivot.id);
    const pivotZoneId = pivotDevice ? scopeToZoneId(pivotDevice.discoveryScope) : null;
    const tgtZoneId = scopeToZoneId(d.discoveryScope);

    if (isDockerNetGateway(d)) {
      // (a) docker-net gateway nodes → its origin's pivot
      const crossZone = pivotZoneId !== null ? pivotZoneId !== tgtZoneId : true;
      edges.push({
        data: {
          id: `db-${pivot.id}-${d.id}`,
          source: String(pivot.id),
          target: String(d.id),
          kind: 'docker-bridge',
          ...(crossZone ? { crossZone: true } : {}),
        },
      });
    } else if (d.publishesHostPort === true) {
      // (b) published-port container → pivot directly
      const crossZone = pivotZoneId !== null ? pivotZoneId !== tgtZoneId : true;
      edges.push({
        data: {
          id: `db-${pivot.id}-${d.id}`,
          source: String(pivot.id),
          target: String(d.id),
          kind: 'docker-bridge',
          ...(crossZone ? { crossZone: true } : {}),
        },
      });

      // Change 1: ALSO wire published container → its docker-net gateway when one exists.
      const slash24 = ipv4Slash24(d.ipAddress);
      const networkGateway = slash24 !== null ? slash24ToDockerGateway.get(slash24) : undefined;
      if (networkGateway) {
        const gwZoneId = scopeToZoneId(networkGateway.discoveryScope);
        const crossZoneGw = tgtZoneId !== gwZoneId;
        edges.push({
          data: {
            id: `db-${d.id}-${networkGateway.id}`,
            source: String(d.id),
            target: String(networkGateway.id),
            kind: 'docker-bridge',
            ...(crossZoneGw ? { crossZone: true } : {}),
          },
        });
      }
    } else {
      // (c) internal-only container → its docker-net gateway (when one exists).
      // Change 2: if no gateway found, emit nothing (remove anti-orphan fallback).
      const slash24 = ipv4Slash24(d.ipAddress);
      const networkGateway = slash24 !== null ? slash24ToDockerGateway.get(slash24) : undefined;

      if (networkGateway) {
        const gwZoneId = scopeToZoneId(networkGateway.discoveryScope);
        const crossZone = tgtZoneId !== gwZoneId;
        edges.push({
          data: {
            id: `db-${d.id}-${networkGateway.id}`,
            source: String(d.id),
            target: String(networkGateway.id),
            kind: 'docker-bridge',
            ...(crossZone ? { crossZone: true } : {}),
          },
        });
      }
      // Change 2: no else — unattached internal containers get zero edges.
    }
  }

  return edges;
}
