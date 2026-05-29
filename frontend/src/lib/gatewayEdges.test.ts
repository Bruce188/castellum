import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { buildGatewayEdges } from './gatewayEdges';
import type { Device, DiscoveryScope } from '../api/types';

function makeDevice(
  id: number,
  ipAddress: string,
  scope: DiscoveryScope,
  hostname: string | null = null,
): Device {
  return {
    id,
    ipAddress,
    hostname,
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
  };
}

describe('buildGatewayEdges', () => {
  it('same_subnet_star_with_dot1', () => {
    const devices: Device[] = [
      makeDevice(1, '192.168.68.1', 'HOME'),
      makeDevice(2, '192.168.68.50', 'HOME'),
      makeDevice(3, '192.168.68.51', 'HOME'),
    ];
    const edges = buildGatewayEdges(devices);
    // 2 peers, both → .1
    const gatewayEdges = edges.filter(e => e.data.kind === 'gateway');
    expect(gatewayEdges).toHaveLength(2);
    expect(gatewayEdges.every(e => e.data.target === '1')).toBe(true);
    expect(gatewayEdges.every(e => e.data.gatewayIp === '192.168.68.1')).toBe(true);
    expect(gatewayEdges.map(e => e.data.source).sort()).toEqual(['2', '3']);
  });

  it('same_subnet_star_without_dot1', () => {
    const devices: Device[] = [
      makeDevice(1, '192.168.68.5', 'HOME'),
      makeDevice(2, '192.168.68.10', 'HOME'),
      makeDevice(3, '192.168.68.15', 'HOME'),
    ];
    const edges = buildGatewayEdges(devices);
    const gatewayEdges = edges.filter(e => e.data.kind === 'gateway');
    expect(gatewayEdges).toHaveLength(2);
    // Lowest IP wins: 192.168.68.5 → device id 1
    expect(gatewayEdges.every(e => e.data.target === '1')).toBe(true);
    expect(gatewayEdges.every(e => e.data.gatewayIp === '192.168.68.5')).toBe(true);
  });

  it('mixed_scope_with_docker_host_at_default_ip', () => {
    // Device 3 at 192.168.68.51 (default docker-host IP) — detected by IP, not hostname.
    // Hostname field is null to reflect the post-fix backend behavior (alias filtered).
    const devices: Device[] = [
      makeDevice(1, '192.168.68.1', 'HOME'),
      makeDevice(2, '192.168.68.50', 'HOME'),
      makeDevice(3, '192.168.68.51', 'HOME', null),
      makeDevice(4, '172.18.0.2', 'DOCKER_BRIDGE'),
      makeDevice(5, '172.18.0.3', 'DOCKER_BRIDGE'),
    ];
    const edges = buildGatewayEdges(devices);
    const gatewayEdges = edges.filter(e => e.data.kind === 'gateway');
    const dockerEdges = edges.filter(e => e.data.kind === 'docker-bridge');

    // Gateway edges within 192.168.68/24: .50 → .1, .51 → .1
    // Within 172.18.0/24: .3 → .2 (lowest-IP fallback since no .1)
    expect(gatewayEdges).toHaveLength(3);
    const home68 = gatewayEdges.filter(e => e.data.gatewayIp === '192.168.68.1');
    expect(home68).toHaveLength(2);
    expect(home68.every(e => e.data.target === '1')).toBe(true);
    expect(home68.map(e => e.data.source).sort()).toEqual(['2', '3']);

    // Docker-bridge synthetic edges: docker host (device 3) → each DOCKER_BRIDGE device.
    expect(dockerEdges).toHaveLength(2);
    expect(dockerEdges.every(e => e.data.source === '3')).toBe(true);
    expect(dockerEdges.map(e => e.data.target).sort()).toEqual(['4', '5']);

    // 172.18.0/24 gateway edge: .3 → .2 (lowest-IP fallback)
    const docker24 = gatewayEdges.find(e => e.data.gatewayIp === '172.18.0.2');
    expect(docker24).toMatchObject({ data: { source: '5', target: '4' } });
  });

  it('docker_bridge_without_host_remains_orphan', () => {
    const devices: Device[] = [
      makeDevice(1, '172.18.0.2', 'DOCKER_BRIDGE'),
      makeDevice(2, '172.18.0.3', 'DOCKER_BRIDGE'),
    ];
    const edges = buildGatewayEdges(devices);
    const dockerEdges = edges.filter(e => e.data.kind === 'docker-bridge');
    // No HOME device matches docker-host heuristic → zero synthetic edges.
    expect(dockerEdges).toHaveLength(0);
    // DOCKER_BRIDGE devices still cluster by /24: 1 gateway-kind edge expected.
    expect(edges).toHaveLength(1);
  });

  it('lone_link_local_device_yields_isolated_affordance_not_zero_edges', () => {
    const devices = [
      makeDevice(1, '192.168.68.1', 'HOME'),
      makeDevice(2, '192.168.68.50', 'HOME'),
      makeDevice(3, '169.254.73.152', 'LINK_LOCAL'),
    ];
    const edges = buildGatewayEdges(devices);
    const isolated = edges.filter(e => e.data.kind === 'isolated');
    expect(isolated).toHaveLength(1);
    expect(isolated[0].data.source).toBe('3');
    expect(isolated[0].data.target).toBe('3'); // self-anchor
    // existing gateway edges for the .68 /24 still present
    expect(edges.some(e => e.data.kind === 'gateway')).toBe(true);
  });

  it('docker_bridge_singleton_does_not_double_emit_isolated', () => {
    // Docker host at default IP (192.168.68.51), null hostname (alias filtered by backend).
    const devices = [
      makeDevice(1, '192.168.68.51', 'HOME', null),
      makeDevice(2, '172.18.0.2', 'DOCKER_BRIDGE'),
    ];
    const edges = buildGatewayEdges(devices);
    // DOCKER_BRIDGE device (id=2) gets a db- edge from the docker host, must NOT also get isolated
    const isolated = edges.filter(e => e.data.kind === 'isolated');
    expect(isolated.map(e => e.data.source)).not.toContain('2');
  });

  describe('localStorage_override_routes_from_overridden_ip', () => {
    beforeEach(() => {
      localStorage.setItem('castellum.topology.docker-host-ip', '192.168.68.99');
    });
    afterEach(() => {
      localStorage.removeItem('castellum.topology.docker-host-ip');
    });

    it('routes docker-bridge edges from the overridden IP', () => {
      const devices: Device[] = [
        makeDevice(1, '192.168.68.99', 'HOME'),
        makeDevice(2, '172.18.0.2', 'DOCKER_BRIDGE'),
      ];
      const edges = buildGatewayEdges(devices);
      const dockerEdges = edges.filter(e => e.data.kind === 'docker-bridge');
      expect(dockerEdges).toHaveLength(1);
      expect(dockerEdges[0].data.source).toBe('1');
      expect(dockerEdges[0].data.target).toBe('2');
    });
  });

  // ────────────────────────────────────────────────────────────────────────
  // AC4 — docker-host detection must NOT rely on hostname string match
  // ────────────────────────────────────────────────────────────────────────

  it('ac4_docker_host_with_alias_hostname_detected_by_ip_not_hostname', () => {
    // Post-fix: device at docker-host IP with a real hostname (alias was filtered by backend)
    const devices: Device[] = [
      makeDevice(1, '192.168.68.51', 'HOME', 'operators-laptop'),
      makeDevice(2, '172.18.0.2', 'DOCKER_BRIDGE'),
    ];
    const edges = buildGatewayEdges(devices);
    const dockerEdges = edges.filter(e => e.data.kind === 'docker-bridge');
    expect(dockerEdges).toHaveLength(1);
    expect(dockerEdges[0].data.source).toBe('1');
  });

  it('ac4_docker_host_null_hostname_detected_by_ip', () => {
    // Bridge alias was filtered → hostname is null; IP-based detection must still work
    const devices: Device[] = [
      makeDevice(1, '192.168.68.51', 'HOME', null),
      makeDevice(2, '172.18.0.2', 'DOCKER_BRIDGE'),
    ];
    const edges = buildGatewayEdges(devices);
    const dockerEdges = edges.filter(e => e.data.kind === 'docker-bridge');
    expect(dockerEdges).toHaveLength(1);
    expect(dockerEdges[0].data.source).toBe('1');
  });

  it('ac4_alias_hostname_on_wrong_ip_is_not_docker_host', () => {
    // A device carrying the alias but NOT at the docker-host IP must not be treated as pivot.
    // With IP-only detection and default docker-host IP (192.168.68.51), this device (99) misses.
    const devices: Device[] = [
      makeDevice(1, '192.168.68.99', 'HOME', 'host.docker.internal'),
      makeDevice(2, '172.18.0.2', 'DOCKER_BRIDGE'),
    ];
    const edges = buildGatewayEdges(devices);
    const dockerEdges = edges.filter(e => e.data.kind === 'docker-bridge');
    expect(dockerEdges).toHaveLength(0);
  });

  it('ac4_docker_bridge_singleton_with_ip_only_host_does_not_emit_isolated', () => {
    // IP-only host detection: device 1 at 192.168.68.51 (no hostname) should rescue device 2
    const devices = [
      makeDevice(1, '192.168.68.51', 'HOME', null),
      makeDevice(2, '172.18.0.2', 'DOCKER_BRIDGE'),
    ];
    const edges = buildGatewayEdges(devices);
    const isolated = edges.filter(e => e.data.kind === 'isolated');
    expect(isolated.map(e => e.data.source)).not.toContain('2');
  });
});
