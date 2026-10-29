import { describe, it, expect, vi } from 'vitest';
import { buildWanEdges, WAN_EDGE_CAP } from './wanEdges';
import type { Device, DeviceRole, DiscoveryScope } from '../api/types';

// Default docker-host IP (DEFAULT_DOCKER_HOST_IP in gatewayEdges) — the HOME
// device a "local"-origin PUBLIC peer resolves to. No localStorage override is
// set in this suite, so the resolver falls back to this address.
const LOCAL_HOST_IP = '192.168.68.51';

function makeDevice(
  id: number,
  ipAddress: string,
  scope: DiscoveryScope,
  deviceRole: DeviceRole = 'UNKNOWN',
  originHostIp = 'local',
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
    originHostIp,
    originHostName: null,
    networkName: null,
  };
}

describe('buildWanEdges', () => {
  it('local_origin_public_anchors_to_originating_host_not_gateway', () => {
    // PUBLIC peers with originHostIp 'local' anchor to the docker-host
    // (192.168.68.51), NOT the LAN gateway/router at .1.
    const devices: Device[] = [
      makeDevice(1, '192.168.68.1', 'HOME', 'ROUTER'), // gateway — must NOT anchor
      makeDevice(2, LOCAL_HOST_IP, 'HOME'),            // the originating (local) host
      makeDevice(3, '8.8.8.8', 'PUBLIC'),
      makeDevice(4, '1.1.1.1', 'PUBLIC'),
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(2);
    expect(edges.every(e => e.data.kind === 'wan')).toBe(true);
    expect(edges.every(e => e.data.source === '2')).toBe(true); // origin host
    expect(edges.every(e => e.data.source !== '1')).toBe(true); // NOT the gateway/router
    expect(edges.every(e => e.classes === 'wan-edge')).toBe(true);
    expect(edges.map(e => e.data.target).sort()).toEqual(['3', '4']);
  });

  it('remote_origin_public_anchors_to_matching_home_host_not_gateway', () => {
    // A PUBLIC peer whose originHostIp names a remote HOME host resolves to
    // that host (by ipAddress), not the gateway.
    const devices: Device[] = [
      makeDevice(1, '192.168.68.1', 'HOME', 'ROUTER'),               // gateway present
      makeDevice(5, '10.0.0.20', 'HOME'),                           // the originating host
      makeDevice(6, '203.0.113.7', 'PUBLIC', 'UNKNOWN', '10.0.0.20'),
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(1);
    expect(edges[0].data).toEqual({ id: 'wan:5-6', source: '5', target: '6', kind: 'wan' });
    expect(edges[0].data.source).not.toBe('1'); // not the gateway
    expect(edges[0].classes).toBe('wan-edge');
  });

  it('remote_origin_multiple_home_matches_lowest_id_wins', () => {
    const devices: Device[] = [
      makeDevice(9, '10.0.0.20', 'HOME'),
      makeDevice(4, '10.0.0.20', 'HOME'), // same IP, lower id → wins
      makeDevice(6, '203.0.113.7', 'PUBLIC', 'UNKNOWN', '10.0.0.20'),
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(1);
    expect(edges[0].data.source).toBe('4');
  });

  it('unresolvable_origin_yields_isolated_self_anchor_not_gateway', () => {
    // originHostIp names a host with no matching HOME device — the peer must
    // self-anchor, NOT fall back to the gateway that is present.
    const devices: Device[] = [
      makeDevice(1, '192.168.68.1', 'HOME', 'ROUTER'), // gateway exists...
      makeDevice(2, '8.8.8.8', 'PUBLIC', 'UNKNOWN', '10.9.9.9'), // ...origin 10.9.9.9 absent
    ];
    expect(buildWanEdges(devices)).toEqual([
      { data: { id: 'wan-iso-2', source: '2', target: '2', kind: 'isolated' } },
    ]);
  });

  it('local_origin_without_docker_host_yields_isolated_self_anchor', () => {
    // origin 'local' but no HOME device at the docker-host IP → unresolvable →
    // isolated self-anchor (not the .1 gateway).
    const devices: Device[] = [
      makeDevice(1, '192.168.68.1', 'HOME', 'ROUTER'), // gateway at .1; docker-host (.51) absent
      makeDevice(2, '8.8.8.8', 'PUBLIC'),
    ];
    expect(buildWanEdges(devices)).toEqual([
      { data: { id: 'wan-iso-2', source: '2', target: '2', kind: 'isolated' } },
    ]);
  });

  it('mixed_origins_resolve_per_device', () => {
    // One peer's origin resolves (→ wan edge), another's does not (→ isolated).
    const devices: Device[] = [
      makeDevice(2, LOCAL_HOST_IP, 'HOME'),                       // local origin host
      makeDevice(3, '8.8.8.8', 'PUBLIC'),                         // origin 'local' → host 2
      makeDevice(4, '1.1.1.1', 'PUBLIC', 'UNKNOWN', '10.9.9.9'),  // origin absent → isolated
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(2);
    const wan = edges.find(e => e.data.target === '3')!;
    const iso = edges.find(e => e.data.target === '4')!;
    expect(wan.data).toEqual({ id: 'wan:2-3', source: '2', target: '3', kind: 'wan' });
    expect(wan.classes).toBe('wan-edge');
    expect(iso.data).toEqual({ id: 'wan-iso-4', source: '4', target: '4', kind: 'isolated' });
    expect(iso.classes).toBeUndefined();
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
      makeDevice(2, LOCAL_HOST_IP, 'HOME'),
    ];
    expect(buildWanEdges(devices)).toEqual([]);
  });

  it('over_cap_public_devices_yields_isolated_self_anchors_with_single_warn', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const devices: Device[] = [
      makeDevice(1, LOCAL_HOST_IP, 'HOME'),
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
      makeDevice(1, LOCAL_HOST_IP, 'HOME'),
      ...Array.from({ length: WAN_EDGE_CAP }, (_, i) =>
        makeDevice(100 + i, `8.8.${Math.floor(i / 256)}.${i % 256}`, 'PUBLIC'),
      ),
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(WAN_EDGE_CAP);
    expect(edges.every(e => e.data.source === '1')).toBe(true);
    expect(edges.every(e => e.data.kind === 'wan')).toBe(true);
  });

  it('edge_def_shape_id_kind_and_class', () => {
    const devices: Device[] = [
      makeDevice(7, LOCAL_HOST_IP, 'HOME'),
      makeDevice(9, '8.8.8.8', 'PUBLIC'),
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(1);
    expect(edges[0]).toEqual({
      data: { id: 'wan:7-9', source: '7', target: '9', kind: 'wan' },
      classes: 'wan-edge',
    });
  });

  it('ipv6_public_devices_count_toward_cap', () => {
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
      makeDevice(1, LOCAL_HOST_IP, 'HOME'),
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

  it('ipv6_public_devices_below_cap_anchor_to_origin_host', () => {
    // A mix of IPv4 and IPv6 PUBLIC devices within cap → all anchor to their
    // local originating host.
    const devices: Device[] = [
      makeDevice(1, LOCAL_HOST_IP, 'HOME'),
      makeDevice(2, '8.8.8.8', 'PUBLIC'),
      makeDevice(3, '2001:db8::1', 'PUBLIC'),
    ];
    const edges = buildWanEdges(devices);
    expect(edges).toHaveLength(2);
    expect(edges.every(e => e.data.source === '1')).toBe(true);
    expect(edges.map(e => e.data.target).sort()).toEqual(['2', '3']);
  });
});
