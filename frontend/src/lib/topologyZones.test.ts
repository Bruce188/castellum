/**
 * Regression lock for zone-id resolution.
 *
 * Primary goal: confirm that docker-net:<network> gateway devices
 * (scope DOCKER_BRIDGE) resolve to 'zone-docker', NOT 'zone-home',
 * despite sharing a .1 IP pattern with home-network gateways.
 *
 * AC5 coverage: ZoneId union, ZONE_DEFINITIONS labels and scopes.
 */

import { describe, it, expect } from 'vitest';
import {
  scopeToZoneId,
  presentZoneIds,
  ZONE_DEFINITIONS,
  ZONE_ORDER,
} from './topologyZones';
import type { ZoneId } from './topologyZones';
import type { Device, DiscoveryScope } from '../api/types';

// ─── minimal fixture factory (mirrors gatewayEdges.test.ts) ──────────────────

function makeDevice(
  id: number,
  ipAddress: string,
  scope: DiscoveryScope,
  hostname: string | null = null,
  publishesHostPort = false,
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
    publishesHostPort,
  };
}

// ─── (a) DOCKER_BRIDGE scope maps to zone-docker ─────────────────────────────

describe('scopeToZoneId', () => {
  it('(a) DOCKER_BRIDGE resolves to zone-docker', () => {
    expect(scopeToZoneId('DOCKER_BRIDGE')).toBe('zone-docker');
  });

  it('(a-falsifiable) DOCKER_BRIDGE must NOT resolve to zone-home', () => {
    expect(scopeToZoneId('DOCKER_BRIDGE')).not.toBe('zone-home');
  });

  // ─── (c) HOME scope maps to zone-home (preserve) ─────────────────────────

  it('(c) HOME resolves to zone-home', () => {
    expect(scopeToZoneId('HOME')).toBe('zone-home');
  });

  it('covers remaining scopes for completeness', () => {
    expect(scopeToZoneId('LINK_LOCAL')).toBe('zone-local');
    expect(scopeToZoneId('LOOPBACK')).toBe('zone-local');
    expect(scopeToZoneId('PUBLIC')).toBe('zone-public');
  });
});

// ─── (b) docker-net gateway device end-to-end zone resolution ────────────────

describe('docker-net gateway device resolves to zone-docker', () => {
  // A docker-net:<network> gateway device: scope DOCKER_BRIDGE, hostname like 'docker-net:foo'.
  // Its IP is the .1 of a Docker bridge subnet (172.18.0.1) — same pattern as a home router.
  // The zone must be determined by discoveryScope, not by IP or hostname pattern.

  const dockerNetGateway = makeDevice(
    1,
    '172.18.0.1',
    'DOCKER_BRIDGE',
    'docker-net:my_network',
    false,
  );

  it('(b) gateway device with scope DOCKER_BRIDGE lands in zone-docker', () => {
    const zone = scopeToZoneId(dockerNetGateway.discoveryScope);
    expect(zone).toBe('zone-docker');
  });

  it('(b-falsifiable) gateway device with scope DOCKER_BRIDGE does NOT land in zone-home', () => {
    const zone = scopeToZoneId(dockerNetGateway.discoveryScope);
    expect(zone).not.toBe('zone-home');
  });

  it('(b) a .1 IP on DOCKER_BRIDGE scope still maps to zone-docker, not zone-home', () => {
    // Regression: a stale comment or mapping reverting DOCKER_BRIDGE → zone-home
    // would route this device into the wrong zone compound node.
    const dotOneGateway = makeDevice(2, '172.18.0.1', 'DOCKER_BRIDGE', 'docker-net:foo', false);
    expect(scopeToZoneId(dotOneGateway.discoveryScope)).toBe('zone-docker');
    expect(scopeToZoneId(dotOneGateway.discoveryScope)).not.toBe('zone-home');
  });

  it('(b) presentZoneIds with DOCKER_BRIDGE scope includes zone-docker, not zone-home', () => {
    const zones = presentZoneIds([dockerNetGateway.discoveryScope]);
    expect(zones).toContain('zone-docker');
    expect(zones).not.toContain('zone-home');
  });
});

// ─── (d) ZoneId union and ZONE_DEFINITIONS legend preserve (AC5) ─────────────

describe('ZONE_DEFINITIONS legend (AC5)', () => {
  // TypeScript enforces the ZoneId union at compile time;
  // these runtime assertions lock the four values for regression.

  const allZoneIds: ZoneId[] = ['zone-home', 'zone-docker', 'zone-local', 'zone-public'];

  it('(d) ZONE_ORDER contains exactly the four expected zone ids', () => {
    expect([...ZONE_ORDER].sort()).toEqual([...allZoneIds].sort());
  });

  it('(d) zone-home definition: label Home / LAN, scopes [HOME]', () => {
    expect(ZONE_DEFINITIONS['zone-home'].label).toBe('Home / LAN');
    expect(ZONE_DEFINITIONS['zone-home'].scopes).toEqual(['HOME']);
  });

  it('(d) zone-docker definition: label Docker, scopes [DOCKER_BRIDGE]', () => {
    expect(ZONE_DEFINITIONS['zone-docker'].label).toBe('Docker');
    expect(ZONE_DEFINITIONS['zone-docker'].scopes).toEqual(['DOCKER_BRIDGE']);
  });

  it('(d) zone-local definition: label Local, scopes [LINK_LOCAL, LOOPBACK]', () => {
    expect(ZONE_DEFINITIONS['zone-local'].label).toBe('Local');
    expect(ZONE_DEFINITIONS['zone-local'].scopes).toContain('LINK_LOCAL');
    expect(ZONE_DEFINITIONS['zone-local'].scopes).toContain('LOOPBACK');
  });

  it('(d) zone-public definition: label External / Public, scopes [PUBLIC]', () => {
    expect(ZONE_DEFINITIONS['zone-public'].label).toBe('External / Public');
    expect(ZONE_DEFINITIONS['zone-public'].scopes).toEqual(['PUBLIC']);
  });

  it('(d) ZONE_DEFINITIONS has entries for every zone id in ZONE_ORDER', () => {
    for (const zoneId of ZONE_ORDER) {
      expect(ZONE_DEFINITIONS).toHaveProperty(zoneId);
    }
  });

  it('(d) DOCKER_BRIDGE scope appears only in zone-docker definition, not zone-home', () => {
    expect(ZONE_DEFINITIONS['zone-docker'].scopes).toContain('DOCKER_BRIDGE');
    expect(ZONE_DEFINITIONS['zone-home'].scopes).not.toContain('DOCKER_BRIDGE');
  });
});
