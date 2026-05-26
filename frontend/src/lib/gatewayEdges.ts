import type { Device } from '../api/types';
import { ipv4Slash24 } from './subnetEdges';

/**
 * Edge produced by {@link buildGatewayEdges}. Two structurally identical kinds
 * coexist so Cytoscape can style them via {@code edge[kind = ...]} selectors:
 *
 * <ul>
 *   <li>{@code gateway} — peer → gateway-of-/24 (solid stroke).</li>
 *   <li>{@code docker-bridge} — docker-host → DOCKER_BRIDGE device (dashed).</li>
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
    kind: 'gateway' | 'docker-bridge';
    gatewayIp?: string;
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
 * Identify the device that hosts Castellum's docker bridge. Heuristic:
 * <ul>
 *   <li>HOME-scope device whose hostname is exactly {@code host.docker.internal}, OR</li>
 *   <li>HOME-scope device whose IP matches
 *       {@code localStorage[castellum.topology.docker-host-ip]} (default
 *       {@code 192.168.68.51}).</li>
 * </ul>
 * Returns {@code null} if no candidate exists, in which case
 * DOCKER_BRIDGE devices remain orphans (no synthetic edges).
 */
function findDockerHost(devices: Device[]): Device | null {
  const override = (typeof localStorage !== 'undefined'
    ? localStorage.getItem(DOCKER_HOST_IP_LS_KEY)
    : null) ?? DEFAULT_DOCKER_HOST_IP;
  for (const d of devices) {
    if (d.discoveryScope !== 'HOME') continue;
    if (d.hostname === 'host.docker.internal') return d;
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
 *   <li>If a docker host can be identified AND any DOCKER_BRIDGE device exists,
 *       emit one synthetic edge per DOCKER_BRIDGE peer from docker host →
 *       DOCKER_BRIDGE device with {@code kind: 'docker-bridge'}.</li>
 *   <li>Singleton groups produce no edges.</li>
 * </ol>
 */
export function buildGatewayEdges(devices: Device[]): GatewayEdge[] {
  if (devices.length === 0) return [];

  const edges: GatewayEdge[] = [];

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
    if (group.length < 2) continue;
    const gateway = pickGateway(group);
    for (const peer of group) {
      if (peer.id === gateway.id) continue;
      edges.push({
        data: {
          id: `g-${peer.id}-${gateway.id}`,
          source: String(peer.id),
          target: String(gateway.id),
          kind: 'gateway',
          gatewayIp: gateway.ipAddress,
        },
      });
    }
  }

  // Step 3: docker-bridge synthetic edges.
  const dockerHost = findDockerHost(devices);
  if (dockerHost) {
    for (const d of devices) {
      if (d.discoveryScope !== 'DOCKER_BRIDGE') continue;
      edges.push({
        data: {
          id: `db-${dockerHost.id}-${d.id}`,
          source: String(dockerHost.id),
          target: String(d.id),
          kind: 'docker-bridge',
        },
      });
    }
  }

  return edges;
}
