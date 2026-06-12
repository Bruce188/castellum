import type { Device } from '../api/types';
import { ipv4Slash24 } from './subnetEdges';

/**
 * Edge produced by {@link buildWanEdges}. Connects the LAN's egress router
 * (the WAN anchor) to a PUBLIC-scope device so external nodes visually hang
 * off the gateway instead of floating isolated inside zone-public.
 *
 * Mirrors the {@link GatewayEdge} def shape: {@code data.kind} drives any
 * {@code edge[kind = ...]} selector while the {@code wan-edge} class carries
 * the dedicated stroke style in TopologyView's stylesheet.
 */
export interface WanEdge {
  data: {
    id: string;
    source: string;
    target: string;
    kind: 'wan';
  };
  classes: 'wan-edge';
}

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
 *   <li>No candidate → {@code null}; PUBLIC nodes stay unanchored.</li>
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

/**
 * Build WAN edges connecting the egress router to every PUBLIC-scope device.
 * Returns {@code []} when no anchor can be identified — PUBLIC nodes still
 * render inside zone-public, just unanchored.
 */
export function buildWanEdges(devices: Device[]): WanEdge[] {
  const publicDevices = devices.filter(d => d.discoveryScope === 'PUBLIC');
  if (publicDevices.length === 0) return [];

  const anchor = pickWanAnchor(devices);
  if (anchor === null) return [];

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
