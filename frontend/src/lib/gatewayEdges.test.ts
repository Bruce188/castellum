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

  it('mixed_scope_with_docker_host_hostname', () => {
    const devices: Device[] = [
      makeDevice(1, '192.168.68.1', 'HOME'),
      makeDevice(2, '192.168.68.50', 'HOME'),
      makeDevice(3, '192.168.68.51', 'HOME', 'host.docker.internal'),
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
});
