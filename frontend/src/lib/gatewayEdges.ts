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
 * is identified by hostname/IP heuristic, not by being the lowest IP of a /24.
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
 * Identify the device that hosts Castellum's docker bridge.
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
 * Build gateway-hub edges that replace the previous flat-star same-subnet
 * topology. Algorithm per docs/plan-v36.md § Task 3.2:
 * <ol>
 *   <li>Group devices by /24 (reuses {@link ipv4Slash24}).</li>
 *   <li>For each group with {@code >= 2} devices, pick a gateway and emit
 *       one edge per non-gateway peer → gateway with
 *       {@code kind: 'gateway'}.</li>
 *   <li>Singleton groups that are NOT rescued by the docker-bridge path emit
 *       a self-anchored {@code kind: 'isolated'} edge (source === target ===
 *       device id) so lone nodes (e.g. APIPA/LINK_LOCAL) carry an explicit
 *       unrouted affordance rather than floating with no context.</li>
 *   <li>If a docker host can be identified AND any DOCKER_BRIDGE device exists,
 *       emit one synthetic edge per DOCKER_BRIDGE peer from docker host →
 *       DOCKER_BRIDGE device with {@code kind: 'docker-bridge'}.</li>
 * </ol>
 */
export function buildGatewayEdges(devices: Device[]): GatewayEdge[] {
  if (devices.length === 0) return [];

  const edges: GatewayEdge[] = [];

  // Build a lookup from device id → device for cross-zone annotation.
  const deviceById = new Map<number, Device>(devices.map(d => [d.id, d]));

  // Compute docker host BEFORE the groups loop so the singleton branch can
  // check whether a DOCKER_BRIDGE device will be rescued by a db- edge.
  const dockerHost = findDockerHost(devices);

  // Step 1+2: gateway edges per /24.
  const groups = new Map<string, Device[]>();
  for (const d of devices) {
    const key = ipv4Slash24(d.ipAddress);
    if (key === null) continue;
    const list = groups.get(key) ?? [];
    list.push(d);
    groups.set(key, list);
  }
  for (const group of groups.values()) {
    if (group.length < 2) {
      // Singleton /24 group: emit an isolated self-anchor unless the device is
      // a DOCKER_BRIDGE device that will be rescued by the docker-bridge path
      // (i.e. a docker host exists and will emit a db- edge for it).
      const lone = group[0];
      const rescuedByDockerBridge = lone.discoveryScope === 'DOCKER_BRIDGE' && dockerHost !== null;
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
  // Routing rules (per AC3):
  //   a) docker-net gateway devices (isDockerNetGateway) → pivot (HOME docker host)
  //   b) published-port containers (publishesHostPort === true) → pivot directly
  //   c) internal-only containers (DOCKER_BRIDGE, not a gateway, publishesHostPort !== true)
  //      → edge from the container to its network's docker-net gateway;
  //      fall back to a pivot edge if no gateway exists for that /24 (avoid orphaning).
  if (dockerHost) {
    // Build a /24 → gateway-device map from the docker-net gateways present.
    const slash24ToGateway = new Map<string, Device>();
    for (const d of devices) {
      if (!isDockerNetGateway(d)) continue;
      const slash24 = ipv4Slash24(d.ipAddress);
      if (slash24 !== null && !slash24ToGateway.has(slash24)) {
        slash24ToGateway.set(slash24, d);
      }
    }

    const pivotDevice = deviceById.get(dockerHost.id);
    const pivotZoneId = pivotDevice ? scopeToZoneId(pivotDevice.discoveryScope) : null;

    for (const d of devices) {
      if (d.discoveryScope !== 'DOCKER_BRIDGE') continue;

      const tgtZoneId = scopeToZoneId(d.discoveryScope);

      if (isDockerNetGateway(d) || d.publishesHostPort === true) {
        // (a) gateway nodes and (b) published-port containers → pivot
        const crossZone = pivotZoneId !== null ? pivotZoneId !== tgtZoneId : true;
        edges.push({
          data: {
            id: `db-${dockerHost.id}-${d.id}`,
            source: String(dockerHost.id),
            target: String(d.id),
            kind: 'docker-bridge',
            ...(crossZone ? { crossZone: true } : {}),
          },
        });
      } else {
        // (c) internal-only container → its docker-net gateway (or pivot as fallback)
        const slash24 = ipv4Slash24(d.ipAddress);
        const networkGateway = slash24 !== null ? slash24ToGateway.get(slash24) : undefined;

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
        } else {
          // Fallback: no gateway for this network — route to pivot to avoid orphaning.
          const crossZone = pivotZoneId !== null ? pivotZoneId !== tgtZoneId : true;
          edges.push({
            data: {
              id: `db-${dockerHost.id}-${d.id}`,
              source: String(dockerHost.id),
              target: String(d.id),
              kind: 'docker-bridge',
              ...(crossZone ? { crossZone: true } : {}),
            },
          });
        }
      }
    }
  }

  return edges;
}
