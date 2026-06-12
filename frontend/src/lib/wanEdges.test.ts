import { describe, it, expect, vi } from 'vitest';
import { buildWanEdges, WAN_EDGE_CAP } from './wanEdges';
import type { Device, DeviceRole, DiscoveryScope } from '../api/types';

function makeDevice(
  id: number,
  ipAddress: string,
  scope: DiscoveryScope,
  deviceRole: DeviceRole = 'UNKNOWN',
): Device {
  return {
    id,
    ipAddress,
    hostname: null,
    macAddress: null,
    firstSeen: '2026-01-01T00:00:00Z',
    lastSeen: '2026-01-01T00:00:00Z',
    criticality: 'MEDIUM',
    discoveryScope: scope,
    lastSeenIface: null,
    discoverySource: null,
    serviceCount: 0,
    osName: null,
    osAccuracy: null,
    osCpe: null,
    publishesHostPort: false,
    deviceRole,
    originHostIp: 'local',
    originHostName: null,
    networkName: null,
  };
}

describe('buildWanEdges', () => {
  it('anchors_public_devices_to_home_router', () => {
    const devices: Device[] = [
      makeDevice(1, '192.168.68.1', 'HOME', 'ROUTER'),
      makeDevice(2, '192.168.68.50', 'HOME'),
      makeDevice(3, '8.8.8.8', 'PUBLIC'),
      makeDevice(4, '1.1.1.1', 'PUBLIC'),
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(2);
    expect(edges.every(e => e.data.source === '1')).toBe(true);
    expect(edges.map(e => e.data.target).sort()).toEqual(['3', '4']);
  });

  it('multiple_routers_lowest_ip_wins', () => {
    const devices: Device[] = [
      makeDevice(1, '192.168.68.254', 'HOME', 'ROUTER'),
      makeDevice(2, '192.168.68.2', 'HOME', 'ROUTER'),
      makeDevice(3, '8.8.8.8', 'PUBLIC'),
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(1);
    // 192.168.68.2 < 192.168.68.254 numerically → device 2 anchors.
    expect(edges[0].data.source).toBe('2');
  });

  it('router_role_must_be_home_scope', () => {
    // A DOCKER_BRIDGE "router" must not anchor; with no HOME .1 either the
    // PUBLIC device falls back to an isolated self-anchor.
    const devices: Device[] = [
      makeDevice(1, '172.17.0.1', 'DOCKER_BRIDGE', 'ROUTER'),
      makeDevice(2, '8.8.8.8', 'PUBLIC'),
    ];
    expect(buildWanEdges(devices)).toEqual([
      { data: { id: 'wan-iso-2', source: '2', target: '2', kind: 'isolated' } },
    ]);
  });

  it('fallback_dot1_of_most_populated_home_slash24', () => {
    // No ROUTER role. Two .1 candidates: 10.0.0.1 (lone) vs 192.168.68.1
    // (shares its /24 with two more HOME devices) → 192.168.68.1 anchors.
    const devices: Device[] = [
      makeDevice(1, '10.0.0.1', 'HOME'),
      makeDevice(2, '192.168.68.1', 'HOME'),
      makeDevice(3, '192.168.68.50', 'HOME'),
      makeDevice(4, '192.168.68.51', 'HOME'),
      makeDevice(5, '8.8.8.8', 'PUBLIC'),
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(1);
    expect(edges[0].data.source).toBe('2');
    expect(edges[0].data.target).toBe('5');
  });

  it('fallback_requires_dot1_no_anchor_yields_isolated_self_anchors', () => {
    // HOME devices exist but none is a ROUTER and none ends in .1 → no anchor
    // → the PUBLIC device gets an isolated self-anchor, not zero edges.
    const devices: Device[] = [
      makeDevice(1, '192.168.68.50', 'HOME'),
      makeDevice(2, '192.168.68.51', 'HOME'),
      makeDevice(3, '8.8.8.8', 'PUBLIC'),
    ];
    expect(buildWanEdges(devices)).toEqual([
      { data: { id: 'wan-iso-3', source: '3', target: '3', kind: 'isolated' } },
    ]);
  });

  it('no_home_devices_yields_isolated_self_anchor_per_public_device', () => {
    const devices: Device[] = [
      makeDevice(1, '8.8.8.8', 'PUBLIC'),
      makeDevice(2, '1.1.1.1', 'PUBLIC'),
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(2);
    expect(edges.map(e => e.data.id).sort()).toEqual(['wan-iso-1', 'wan-iso-2']);
    expect(edges.every(e => e.data.source === e.data.target)).toBe(true);
    expect(edges.every(e => e.data.kind === 'isolated')).toBe(true);
    // Self-anchors must NOT carry the wan-edge stroke class.
    expect(edges.every(e => e.classes === undefined)).toBe(true);
  });

  it('no_public_devices_yields_empty', () => {
    const devices: Device[] = [
      makeDevice(1, '192.168.68.1', 'HOME', 'ROUTER'),
      makeDevice(2, '192.168.68.50', 'HOME'),
    ];
    expect(buildWanEdges(devices)).toEqual([]);
  });

  it('over_cap_public_devices_yields_isolated_self_anchors_with_single_warn', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const devices: Device[] = [
      makeDevice(1, '192.168.68.1', 'HOME', 'ROUTER'),
      ...Array.from({ length: WAN_EDGE_CAP + 1 }, (_, i) =>
        makeDevice(100 + i, `8.8.${Math.floor(i / 256)}.${i % 256}`, 'PUBLIC'),
      ),
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(WAN_EDGE_CAP + 1);
    expect(edges.every(e => e.data.kind === 'isolated')).toBe(true);
    expect(edges.every(e => e.data.source === e.data.target)).toBe(true);
    expect(edges.every(e => e.data.id.startsWith('wan-iso-'))).toBe(true);
    expect(edges.every(e => e.classes === undefined)).toBe(true);
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });

  it('exactly_cap_public_devices_builds_all_edges', () => {
    const devices: Device[] = [
      makeDevice(1, '192.168.68.1', 'HOME', 'ROUTER'),
      ...Array.from({ length: WAN_EDGE_CAP }, (_, i) =>
        makeDevice(100 + i, `8.8.${Math.floor(i / 256)}.${i % 256}`, 'PUBLIC'),
      ),
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(WAN_EDGE_CAP);
    expect(edges.every(e => e.data.source === '1')).toBe(true);
  });

  it('edge_def_shape_id_kind_and_class', () => {
    const devices: Device[] = [
      makeDevice(7, '192.168.68.1', 'HOME', 'ROUTER'),
      makeDevice(9, '8.8.8.8', 'PUBLIC'),
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(1);
    expect(edges[0]).toEqual({
      data: { id: 'wan:7-9', source: '7', target: '9', kind: 'wan' },
      classes: 'wan-edge',
    });
  });

  it('fallback_equal_population_slash24_tiebreak_lower_dot1_wins', () => {
    // Two /24 groups with identical HOME population (2 each), both having a .1 device.
    // 10.0.0.1 (numerically lower) should beat 192.168.1.1 as the anchor.
    const devices: Device[] = [
      makeDevice(1, '10.0.0.1', 'HOME'),
      makeDevice(2, '10.0.0.50', 'HOME'),
      makeDevice(3, '192.168.1.1', 'HOME'),
      makeDevice(4, '192.168.1.50', 'HOME'),
      makeDevice(5, '8.8.8.8', 'PUBLIC'),
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(1);
    // 10.0.0.1 < 192.168.1.1 numerically → device 1 anchors.
    expect(edges[0].data.source).toBe('1');
    expect(edges[0].data.target).toBe('5');
  });

  it('router_non_ipv4_address_id_fallback_lowest_id_wins', () => {
    // Two HOME ROUTERs with IPv6 addresses — ipToInt returns null for both
    // so byIpThenId falls back to a.id - b.id; the lowest id (10) anchors.
    const devices: Device[] = [
      makeDevice(20, '2001:db8::2', 'HOME', 'ROUTER'),
      makeDevice(10, '2001:db8::1', 'HOME', 'ROUTER'),
      makeDevice(99, '8.8.8.8', 'PUBLIC'),
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(1);
    expect(edges[0].data.source).toBe('10');
  });

  it('ipv6_public_devices_receive_wan_edges_and_count_toward_cap', () => {
    // IPv6 PUBLIC devices are included in publicDevices (scope-only filter).
    // 63 IPv4 + 2 IPv6 PUBLIC = 65 > WAN_EDGE_CAP (64) → cap warning →
    // isolated self-anchors for all 65.
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const ipv4Public = Array.from({ length: 63 }, (_, i) =>
      makeDevice(100 + i, `8.8.${Math.floor(i / 256)}.${i % 256}`, 'PUBLIC'),
    );
    const ipv6Public = [
      makeDevice(200, '2001:db8::1', 'PUBLIC'),
      makeDevice(201, '2001:db8::2', 'PUBLIC'),
    ];
    const devices: Device[] = [
      makeDevice(1, '192.168.68.1', 'HOME', 'ROUTER'),
      ...ipv4Public,
      ...ipv6Public,
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(65);
    expect(edges.every(e => e.data.kind === 'isolated')).toBe(true);
    expect(edges.every(e => e.data.source === e.data.target)).toBe(true);
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });

  it('ipv6_public_devices_below_cap_receive_wan_edges', () => {
    // A mix of IPv4 and IPv6 PUBLIC devices within cap → all get edges.
    const devices: Device[] = [
      makeDevice(1, '192.168.68.1', 'HOME', 'ROUTER'),
      makeDevice(2, '8.8.8.8', 'PUBLIC'),
      makeDevice(3, '2001:db8::1', 'PUBLIC'),
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(2);
    expect(edges.every(e => e.data.source === '1')).toBe(true);
    expect(edges.map(e => e.data.target).sort()).toEqual(['2', '3']);
  });
});
