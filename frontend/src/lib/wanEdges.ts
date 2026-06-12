import type { Device } from '../api/types';
import { ipv4Slash24 } from './subnetEdges';

/**
 * Edge produced by {@link buildWanEdges}. Two kinds coexist:
 * <ul>
 *   <li>{@code wan} — connects the LAN's egress router (the WAN anchor) to a
 *       PUBLIC-scope device so external nodes visually hang off the gateway
 *       instead of floating isolated inside zone-public. Carries the
 *       {@code wan-edge} class for the dedicated stroke style in
 *       TopologyView's stylesheet.</li>
 *   <li>{@code isolated} — self-anchor (source === target) emitted for each
 *       PUBLIC device when no WAN anchor is resolvable or the cap is
 *       exceeded, so PUBLIC nodes always carry the explicit unrouted
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
 * subnet-cap (64). Past it, the single-anchor fan-in becomes the densest
 * edge cluster in the graph and degrades the cose-bilkent layout, so the
 * anchored edge set is dropped and PUBLIC devices fall back to isolated
 * self-anchors instead. Self-loops don't create the dense single-anchor
 * fan-in the cap exists to prevent, so emitting them over-cap is consistent
 * with the cap's rationale.
 */
export const WAN_EDGE_CAP = 64;

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

/** Sort comparator: numerically lowest IP first; tie-break (defensive) on lowest id. */
function byIpThenId(a: Device, b: Device): number {
  const ai = ipToInt(a.ipAddress);
  const bi = ipToInt(b.ipAddress);
  if (ai !== null && bi !== null && ai !== bi) return ai - bi;
  return a.id - b.id;
}

/**
 * Pick the LAN's egress router — the anchor that WAN edges fan out from:
 * <ol>
 *   <li>HOME-scope device with {@code deviceRole === 'ROUTER'}; if several,
 *       the numerically lowest IP wins.</li>
 *   <li>Fallback: the HOME device whose IPv4 ends in {@code .1} sharing its
 *       /24 with the largest number of HOME devices (most-populated subnet's
 *       {@code .1} is the likeliest default gateway).</li>
 *   <li>No candidate → {@code null}; PUBLIC nodes fall back to isolated
 *       self-anchors.</li>
 * </ol>
 */
function pickWanAnchor(devices: Device[]): Device | null {
  const home = devices.filter(d => d.discoveryScope === 'HOME');

  // (a) Explicit ROUTER role wins outright.
  const routers = home.filter(d => d.deviceRole === 'ROUTER');
  if (routers.length > 0) {
    return [...routers].sort(byIpThenId)[0];
  }

  // (b) .1-per-/24 heuristic, weighted by HOME population of the /24.
  const groups = new Map<string, Device[]>();
  for (const d of home) {
    const key = ipv4Slash24(d.ipAddress);
    if (key === null) continue;
    const list = groups.get(key) ?? [];
    list.push(d);
    groups.set(key, list);
  }
  let best: { dot1: Device; size: number } | null = null;
  for (const group of groups.values()) {
    const dot1 = group.find(d => lastOctet(d.ipAddress) === 1);
    if (!dot1) continue;
    if (
      best === null ||
      group.length > best.size ||
      (group.length === best.size && byIpThenId(dot1, best.dot1) < 0)
    ) {
      best = { dot1, size: group.length };
    }
  }
  return best?.dot1 ?? null;
}

/** One isolated self-anchor (source === target) per PUBLIC device. */
function buildIsolatedSelfAnchors(publicDevices: Device[]): WanEdge[] {
  return publicDevices.map(d => ({
    data: {
      id: `wan-iso-${d.id}`,
      source: String(d.id),
      target: String(d.id),
      kind: 'isolated' as const,
    },
  }));
}

/**
 * Build WAN edges connecting the egress router to every PUBLIC-scope device.
 * When no anchor can be identified, or when the PUBLIC count exceeds
 * {@link WAN_EDGE_CAP} (one console.warn), returns one {@code kind:
 * 'isolated'} self-anchor per PUBLIC device instead — PUBLIC nodes always
 * carry at least the explicit unrouted affordance rather than rendering
 * edge-less. The {@code wan-iso-} id prefix cannot collide with
 * gatewayEdges' {@code iso-} ids because gatewayEdges no longer emits
 * anything for PUBLIC devices.
 */
export function buildWanEdges(devices: Device[]): WanEdge[] {
  const publicDevices = devices.filter(d => d.discoveryScope === 'PUBLIC');
  if (publicDevices.length === 0) return [];
  if (publicDevices.length > WAN_EDGE_CAP) {
    console.warn(
      `buildWanEdges: WAN-edge cap (${WAN_EDGE_CAP}) exceeded — ${publicDevices.length} PUBLIC devices fall back to isolated self-anchors`,
    );
    return buildIsolatedSelfAnchors(publicDevices);
  }

  const anchor = pickWanAnchor(devices);
  if (anchor === null) return buildIsolatedSelfAnchors(publicDevices);

  return publicDevices.map(d => ({
    data: {
      id: `wan:${anchor.id}-${d.id}`,
      source: String(anchor.id),
      target: String(d.id),
      kind: 'wan' as const,
    },
    classes: 'wan-edge' as const,
  }));
}
