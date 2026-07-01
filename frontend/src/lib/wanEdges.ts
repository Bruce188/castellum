import type { Device } from '../api/types';
import { findDockerHost } from './gatewayEdges';

/**
 * Edge produced by {@link buildWanEdges}. Two kinds coexist:
 * <ul>
 *   <li>{@code wan} — connects a PUBLIC-scope peer's originating host (the
 *       HOME device from whose connection table the external peer was
 *       observed) to the peer, so external nodes visually hang off the host
 *       that actually reached them instead of floating isolated inside
 *       zone-public. Carries the {@code wan-edge} class for the dedicated
 *       stroke style in TopologyView's stylesheet.</li>
 *   <li>{@code isolated} — self-anchor (source === target) emitted for each
 *       PUBLIC device whose originating host is unresolvable, or when the cap
 *       is exceeded, so PUBLIC nodes always carry the explicit unrouted
 *       affordance instead of rendering edge-less. No {@code wan-edge}
 *       class — these take the same treatment as gatewayEdges' isolated
 *       self-anchors via {@code edge[kind = ...]} selectors. The
 *       {@code wan-iso-} id prefix cannot collide with gatewayEdges'
 *       {@code iso-} ids because gatewayEdges no longer emits anything for
 *       PUBLIC devices (wanEdges owns their anchoring).</li>
 * </ul>
 *
 * Mirrors the {@link GatewayEdge} def shape: {@code data.kind} drives any
 * {@code edge[kind = ...]} selector while the optional {@code wan-edge}
 * class carries the dedicated stroke style for anchored WAN edges only.
 */
export interface WanEdge {
  data: {
    id: string;
    source: string;
    target: string;
    kind: 'wan' | 'isolated';
  };
  classes?: 'wan-edge';
}

/**
 * Ceiling on PUBLIC devices anchored by WAN edges — mirrors GraphBuilder's
 * subnet-cap (64). Past it, the per-origin fan-in becomes the densest edge
 * cluster in the graph and degrades the cose-bilkent layout, so the anchored
 * edge set is dropped and PUBLIC devices fall back to isolated self-anchors
 * instead. Self-loops don't create the dense fan-in the cap exists to prevent,
 * so emitting them over-cap is consistent with the cap's rationale.
 */
export const WAN_EDGE_CAP = 64;

/** One isolated self-anchor (source === target) for a PUBLIC device. */
function isolatedSelfAnchor(d: Device): WanEdge {
  return {
    data: {
      id: `wan-iso-${d.id}`,
      source: String(d.id),
      target: String(d.id),
      kind: 'isolated',
    },
  };
}

/**
 * Resolve the originating host for the PUBLIC peers, keyed by their
 * {@code originHostIp}. Mirrors gatewayEdges' {@code findDockerHosts}:
 * <ul>
 *   <li>{@code "local"} → the SAME resolver gatewayEdges uses for the local
 *       docker-bridge origin ({@link findDockerHost}: the HOME device matching
 *       {@code localStorage[castellum.topology.docker-host-ip]}, default
 *       192.168.68.51).</li>
 *   <li>any other {@code originHostIp} → the HOME-scope device whose
 *       {@code ipAddress} equals it (min by id when several qualify).</li>
 * </ul>
 * Origins with no matching host are omitted — their peers fall back to an
 * isolated self-anchor (never the gateway).
 */
function resolveOriginHosts(devices: Device[], publicDevices: Device[]): Map<string, Device> {
  const hostByOrigin = new Map<string, Device>();

  // Distinct origins among the PUBLIC peers.
  const origins = new Set<string>();
  for (const d of publicDevices) origins.add(d.originHostIp);

  // HOME-by-IP lookup for non-local resolution.
  const homeByIp = new Map<string, Device[]>();
  for (const d of devices) {
    if (d.discoveryScope !== 'HOME') continue;
    const list = homeByIp.get(d.ipAddress) ?? [];
    list.push(d);
    homeByIp.set(d.ipAddress, list);
  }

  for (const origin of origins) {
    if (origin === 'local') {
      // Reuse gatewayEdges' docker-host resolver for the local origin.
      const host = findDockerHost(devices);
      if (host !== null) hostByOrigin.set('local', host);
    } else {
      // Non-local: HOME device whose IP matches the origin host IP, min-by-id.
      const candidates = homeByIp.get(origin) ?? [];
      if (candidates.length > 0) {
        hostByOrigin.set(origin, candidates.reduce((a, b) => (a.id <= b.id ? a : b)));
      }
      // No match → origin omitted; its peers become isolated self-anchors.
    }
  }

  return hostByOrigin;
}

/**
 * Build WAN edges connecting each PUBLIC-scope device to its originating host —
 * the HOME device from whose connection table the external peer was observed,
 * resolved per-peer via {@code originHostIp} (reusing gatewayEdges' docker-host
 * resolver for the {@code "local"} origin). When a peer's originating host is
 * unresolvable it gets a {@code kind: 'isolated'} self-anchor instead — never a
 * gateway fallback — so PUBLIC nodes always carry at least the explicit
 * unrouted affordance rather than rendering edge-less. When the PUBLIC count
 * exceeds {@link WAN_EDGE_CAP} (one console.warn) every PUBLIC device falls
 * back to an isolated self-anchor. The {@code wan-iso-} id prefix cannot
 * collide with gatewayEdges' {@code iso-} ids because gatewayEdges no longer
 * emits anything for PUBLIC devices.
 */
export function buildWanEdges(devices: Device[]): WanEdge[] {
  const publicDevices = devices.filter(d => d.discoveryScope === 'PUBLIC');
  if (publicDevices.length === 0) return [];
  if (publicDevices.length > WAN_EDGE_CAP) {
    console.warn(
      `buildWanEdges: WAN-edge cap (${WAN_EDGE_CAP}) exceeded — ${publicDevices.length} PUBLIC devices fall back to isolated self-anchors`,
    );
    return publicDevices.map(isolatedSelfAnchor);
  }

  const hostByOrigin = resolveOriginHosts(devices, publicDevices);

  return publicDevices.map(peer => {
    const host = hostByOrigin.get(peer.originHostIp);
    if (host === undefined) return isolatedSelfAnchor(peer);
    return {
      data: {
        id: `wan:${host.id}-${peer.id}`,
        source: String(host.id),
        target: String(peer.id),
        kind: 'wan' as const,
      },
      classes: 'wan-edge' as const,
    };
  });
}
