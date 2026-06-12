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
    // A DOCKER_BRIDGE "router" must not anchor; with no HOME .1 either → [].
    const devices: Device[] = [
      makeDevice(1, '172.17.0.1', 'DOCKER_BRIDGE', 'ROUTER'),
      makeDevice(2, '8.8.8.8', 'PUBLIC'),
    ];
    expect(buildWanEdges(devices)).toEqual([]);
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

  it('fallback_requires_dot1_no_anchor_yields_empty', () => {
    // HOME devices exist but none is a ROUTER and none ends in .1 → no anchor.
    const devices: Device[] = [
      makeDevice(1, '192.168.68.50', 'HOME'),
      makeDevice(2, '192.168.68.51', 'HOME'),
      makeDevice(3, '8.8.8.8', 'PUBLIC'),
    ];
    expect(buildWanEdges(devices)).toEqual([]);
  });

  it('no_home_devices_yields_empty', () => {
    const devices: Device[] = [
      makeDevice(1, '8.8.8.8', 'PUBLIC'),
      makeDevice(2, '1.1.1.1', 'PUBLIC'),
    ];
    expect(buildWanEdges(devices)).toEqual([]);
  });

  it('no_public_devices_yields_empty', () => {
    const devices: Device[] = [
      makeDevice(1, '192.168.68.1', 'HOME', 'ROUTER'),
      makeDevice(2, '192.168.68.50', 'HOME'),
    ];
    expect(buildWanEdges(devices)).toEqual([]);
  });

  it('over_cap_public_devices_yields_empty_with_single_warn', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const devices: Device[] = [
      makeDevice(1, '192.168.68.1', 'HOME', 'ROUTER'),
      ...Array.from({ length: WAN_EDGE_CAP + 1 }, (_, i) =>
        makeDevice(100 + i, `8.8.${Math.floor(i / 256)}.${i % 256}`, 'PUBLIC'),
      ),
    ];
    expect(buildWanEdges(devices)).toEqual([]);
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
});
