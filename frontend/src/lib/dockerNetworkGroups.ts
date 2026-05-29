/**
 * Docker compose-project / network sub-box grouping.
 *
 * The backend upserts one synthetic gateway device per docker network:
 *   hostname  = `docker-net:<networkName>`  (e.g. "docker-net:supabase_network_supabase")
 *   ipAddress = x.y.z.1  (the `.1` of the network's /24)
 *   scope     = DOCKER_BRIDGE
 *
 * This module builds the compound-node IDs and membership needed to render a
 * nested two-level topology inside the Docker zone:
 *
 *   zone-docker  (outer zone compound)
 *     └─ docker-net:<name>  (network sub-box compound, one per docker network)
 *           ├─ docker-net:<name> gateway node (the synthetic device itself)
 *           └─ container nodes whose IP shares the /24 with the gateway
 *
 * Containers with no matching docker-net gateway (e.g. stale ARP entries on
 * 172.18.x with no gateway present) fall into a single "unattached" sub-box so
 * the graph never crashes or leaves orphaned parents.
 */

import type { Device } from '../api/types';
import { ipv4Slash24 } from './subnetEdges';

/** Prefix that identifies a synthetic docker-network gateway node. */
export const DOCKER_NET_HOSTNAME_PREFIX = 'docker-net:';

/** Compound-node id for the fallback "unattached" sub-box. */
export const DOCKER_UNATTACHED_GROUP_ID = 'docker-net-unattached';

export interface DockerNetworkGroup {
  /** Cytoscape compound-node id, e.g. `docker-net-group-bridge`. */
  groupId: string;
  /** Human-readable label shown on the compound box, e.g. "bridge". */
  label: string;
  /** Device ids belonging to this group (gateway + containers). */
  memberIds: Set<number>;
  /**
   * When true the group represents stale/unattached devices (ARP residue with no
   * running container or gateway).  Renderers should apply a muted visual style.
   * Named network groups always carry false; the unattached fallback group carries true.
   */
  muted: boolean;
}

/**
 * Returns whether a device is a synthetic docker-network gateway.
 * Gateway nodes have hostname `docker-net:<networkName>`.
 */
export function isDockerNetGateway(device: Device): boolean {
  return (
    device.discoveryScope === 'DOCKER_BRIDGE' &&
    device.hostname !== null &&
    device.hostname.startsWith(DOCKER_NET_HOSTNAME_PREFIX)
  );
}

/**
 * Extracts the network name from a docker-net gateway hostname.
 * `docker-net:supabase_network_supabase` → `supabase_network_supabase`
 */
export function dockerNetworkName(hostname: string): string {
  return hostname.startsWith(DOCKER_NET_HOSTNAME_PREFIX)
    ? hostname.slice(DOCKER_NET_HOSTNAME_PREFIX.length)
    : hostname;
}

/**
 * Cytoscape compound-node id for a docker network group.
 * Uses a stable, dom-safe prefix to avoid collisions with numeric device ids.
 * The network name is slugified (non-alphanumeric/dash/underscore → `_`) because
 * spaces, dots, or `#` in a cytoscape id/selector can cause selector parse errors.
 * The raw name is preserved separately as the human-readable LABEL.
 */
export function dockerNetworkGroupId(networkName: string): string {
  const slug = networkName.replace(/[^a-zA-Z0-9_-]/g, '_');
  return `docker-net-group-${slug}`;
}

/**
 * Builds the list of per-network sub-box groups for all DOCKER_BRIDGE devices.
 *
 * Algorithm:
 * 1. Collect all docker-net gateway devices (hostname starts with `docker-net:`).
 * 2. Build a /24 → networkName map from those gateways.
 * 3. For every DOCKER_BRIDGE device assign it to the group whose gateway /24
 *    matches the container's /24.  Gateways assign to their own group.
 * 4. DOCKER_BRIDGE devices with no matching gateway go to the unattached group.
 * 5. Return only non-empty groups; omit empty ones.
 */
export function buildDockerNetworkGroups(devices: Device[]): DockerNetworkGroup[] {
  // Step 1: find all docker-net gateway devices.
  const gateways = devices.filter(isDockerNetGateway);

  // Step 2: map /24 prefix → group info.
  // Note: two docker networks can never share a /24 — docker guarantees distinct subnets
  // per network, so the first gateway for a given /24 always wins if duplicates ever appear.
  const slash24ToGroup = new Map<string, DockerNetworkGroup>();
  for (const gw of gateways) {
    const slash24 = ipv4Slash24(gw.ipAddress);
    if (slash24 === null) continue;
    const name = dockerNetworkName(gw.hostname!);
    const gid = dockerNetworkGroupId(name);
    if (!slash24ToGroup.has(slash24)) {
      slash24ToGroup.set(slash24, { groupId: gid, label: name, memberIds: new Set(), muted: false });
    }
    // Add the gateway itself to its own group.
    slash24ToGroup.get(slash24)!.memberIds.add(gw.id);
  }

  // Step 3 + 4: assign every DOCKER_BRIDGE device to its group.
  const unattachedIds = new Set<number>();
  for (const d of devices) {
    if (d.discoveryScope !== 'DOCKER_BRIDGE') continue;
    if (isDockerNetGateway(d)) continue; // already added above
    const slash24 = ipv4Slash24(d.ipAddress);
    const group = slash24 !== null ? slash24ToGroup.get(slash24) : undefined;
    if (group) {
      group.memberIds.add(d.id);
    } else {
      unattachedIds.add(d.id);
    }
  }

  // Step 5: collect non-empty groups in stable insertion order.
  const result: DockerNetworkGroup[] = [];
  for (const g of slash24ToGroup.values()) {
    if (g.memberIds.size > 0) result.push(g);
  }
  if (unattachedIds.size > 0) {
    result.push({
      groupId: DOCKER_UNATTACHED_GROUP_ID,
      label: 'Docker (unattached)',
      memberIds: unattachedIds,
      muted: true,
    });
  }
  return result;
}
