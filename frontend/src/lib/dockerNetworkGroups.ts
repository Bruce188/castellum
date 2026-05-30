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
 * Returns the display label for a docker network name.
 * The raw `bridge` network (Docker's default) is labeled `bridge (default)`
 * to communicate its role without changing its `groupId` (which stays
 * `docker-net-group-bridge` so existing Cytoscape selectors are unaffected).
 */
function networkDisplayLabel(networkName: string): string {
  return networkName === 'bridge' ? 'bridge (default)' : networkName;
}

/**
 * Builds the list of per-network sub-box groups for all DOCKER_BRIDGE devices.
 *
 * Primary algorithm (when `networkName` is present on a container):
 * 1. Group containers by `networkName` — keyed via `dockerNetworkGroupId(networkName)`.
 *    The raw `bridge` network renders as `bridge (default)` (display-only; groupId unchanged).
 * 2. Co-group synthetic gateway devices (hostname `docker-net:<name>`) with their
 *    same-name containers — the gateway's `dockerNetworkName(hostname)` must equal the
 *    container's `networkName` for the 1:1 NO-OP invariant.
 *
 * Fallback (when `networkName` is null):
 * 3. Build a /24 → networkName map from gateway hostnames.
 * 4. Assign the device to the group whose gateway /24 matches the container's /24.
 * 5. Devices with neither a `networkName` nor a matching gateway → unattached group.
 *
 * Return only non-empty groups in stable insertion order.
 */
export function buildDockerNetworkGroups(devices: Device[]): DockerNetworkGroup[] {
  // Build a name→group map and a /24→group map from gateway devices.
  // Gateways are always assigned to their own group (they have no networkName, just hostname).
  const nameToGroup = new Map<string, DockerNetworkGroup>();
  const slash24ToGroup = new Map<string, DockerNetworkGroup>();

  // First pass: create groups from gateway devices (they anchor the name→group mapping).
  const gateways = devices.filter(isDockerNetGateway);
  for (const gw of gateways) {
    const name = dockerNetworkName(gw.hostname!);
    const gid = dockerNetworkGroupId(name);
    if (!nameToGroup.has(name)) {
      nameToGroup.set(name, {
        groupId: gid,
        label: networkDisplayLabel(name),
        memberIds: new Set(),
        muted: false,
      });
    }
    nameToGroup.get(name)!.memberIds.add(gw.id);

    // Also register by /24 for the fallback path (null-networkName containers).
    const slash24 = ipv4Slash24(gw.ipAddress);
    if (slash24 !== null && !slash24ToGroup.has(slash24)) {
      slash24ToGroup.set(slash24, nameToGroup.get(name)!);
    }
  }

  // Second pass: assign DOCKER_BRIDGE non-gateway devices.
  const unattachedIds = new Set<number>();
  for (const d of devices) {
    if (d.discoveryScope !== 'DOCKER_BRIDGE') continue;
    if (isDockerNetGateway(d)) continue; // already added above

    if (d.networkName !== null) {
      // Primary path: group by networkName.
      const name = d.networkName;
      const gid = dockerNetworkGroupId(name);
      if (!nameToGroup.has(name)) {
        // Create the group if no gateway has been seen yet for this network.
        nameToGroup.set(name, {
          groupId: gid,
          label: networkDisplayLabel(name),
          memberIds: new Set(),
          muted: false,
        });
      }
      nameToGroup.get(name)!.memberIds.add(d.id);
    } else {
      // Fallback path: group by /24 → gateway inference (legacy behaviour).
      const slash24 = ipv4Slash24(d.ipAddress);
      const group = slash24 !== null ? slash24ToGroup.get(slash24) : undefined;
      if (group) {
        group.memberIds.add(d.id);
      } else {
        unattachedIds.add(d.id);
      }
    }
  }

  // Collect non-empty groups in stable insertion order.
  const result: DockerNetworkGroup[] = [];
  for (const g of nameToGroup.values()) {
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
