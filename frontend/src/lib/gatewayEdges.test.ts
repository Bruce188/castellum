import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { buildGatewayEdges } from './gatewayEdges';
import type { Device, DiscoveryScope } from '../api/types';

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
    // Devices 4+5 are DOCKER_BRIDGE on 172.18.0/24 with NO docker-net gateway →
    // unattached: they get ZERO docker-bridge edges and ZERO gateway-kind edges (Change 2).
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

    // Gateway edges within 192.168.68/24 only: .50 → .1, .51 → .1
    // 172.18.0/24 has no docker-net gateway — unattached devices emit NO gateway edge (Change 2)
    expect(gatewayEdges).toHaveLength(2);
    const home68 = gatewayEdges.filter(e => e.data.gatewayIp === '192.168.68.1');
    expect(home68).toHaveLength(2);
    expect(home68.every(e => e.data.target === '1')).toBe(true);
    expect(home68.map(e => e.data.source).sort()).toEqual(['2', '3']);

    // No docker-bridge edges: unattached DOCKER_BRIDGE devices get zero edges (Change 2)
    expect(dockerEdges).toHaveLength(0);

    // No 172.18.0/24 gateway-kind edge between the two unattached devices (Change 2)
    const docker24 = gatewayEdges.find(e => e.data.gatewayIp === '172.18.0.2');
    expect(docker24).toBeUndefined();
  });

  it('docker_bridge_without_host_remains_orphan', () => {
    // Two DOCKER_BRIDGE devices on 172.18.0/24, no HOME device, no docker-net gateway.
    // They are unattached. Change 2: NO edges at all (no docker-bridge, no gateway-kind).
    const devices: Device[] = [
      makeDevice(1, '172.18.0.2', 'DOCKER_BRIDGE'),
      makeDevice(2, '172.18.0.3', 'DOCKER_BRIDGE'),
    ];
    const edges = buildGatewayEdges(devices);
    const dockerEdges = edges.filter(e => e.data.kind === 'docker-bridge');
    // No HOME device matches docker-host heuristic → zero synthetic docker-bridge edges.
    expect(dockerEdges).toHaveLength(0);
    // Unattached DOCKER_BRIDGE devices also emit NO gateway-kind edges between themselves (Change 2).
    expect(edges).toHaveLength(0);
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

  // ────────────────────────────────────────────────────────────────────────
  // Task 2.1 — publishesHostPort-branched gateway edge model
  // ────────────────────────────────────────────────────────────────────────

  describe('publishesHostPort branching', () => {
    // Pivot (docker host): HOME device at default IP 192.168.68.51 (id=1)
    // docker-net gateway for network "net_a":  172.18.0.1, DOCKER_BRIDGE, hostname="docker-net:net_a" (id=2)
    // published-port container in net_a:       172.18.0.5, DOCKER_BRIDGE, publishesHostPort=true  (id=3)
    // internal-only container in net_a:        172.18.0.6, DOCKER_BRIDGE, publishesHostPort=false (id=4)

    const pivot = makeDevice(1, '192.168.68.51', 'HOME', null, false);
    const netAGateway = makeDevice(2, '172.18.0.1', 'DOCKER_BRIDGE', 'docker-net:net_a', false);
    const publishedContainer = makeDevice(3, '172.18.0.5', 'DOCKER_BRIDGE', null, true);
    const internalContainer = makeDevice(4, '172.18.0.6', 'DOCKER_BRIDGE', null, false);

    // ── RECONCILED (a): Change 1 — published container in a gatewayed network gets BOTH edges ──
    // Old contract: published container → pivot only (exactly one edge).
    // New contract: published container → gateway (new) AND → pivot (kept).
    it('(a) publishesHostPort:true container in a gatewayed network gets edge to pivot AND edge to gateway', () => {
      const devices = [pivot, netAGateway, publishedContainer];
      const edges = buildGatewayEdges(devices);
      const dbEdges = edges.filter(e => e.data.kind === 'docker-bridge');

      // The pivot must still have a docker-bridge edge to the published container (existing behaviour)
      const pivotToPublished = dbEdges.filter(
        e => e.data.source === String(pivot.id) && e.data.target === String(publishedContainer.id),
      );
      expect(pivotToPublished).toHaveLength(1);

      // NEW (Change 1): the published container must ALSO have a docker-bridge edge to the docker-net gateway
      const publishedToGateway = dbEdges.filter(
        e => e.data.source === String(publishedContainer.id) && e.data.target === String(netAGateway.id),
      );
      expect(
        publishedToGateway,
        'published container in a gatewayed network must have a docker-bridge edge to its docker-net gateway',
      ).toHaveLength(1);
    });

    it('(b) internal-only container routes to docker-net gateway, NOT to the pivot', () => {
      const devices = [pivot, netAGateway, internalContainer];
      const edges = buildGatewayEdges(devices);
      const dbEdges = edges.filter(e => e.data.kind === 'docker-bridge');

      // Internal container must NOT appear as the target of a pivot-sourced docker-bridge edge
      const pivotToInternal = dbEdges.filter(
        e => e.data.source === String(pivot.id) && e.data.target === String(internalContainer.id),
      );
      expect(pivotToInternal).toHaveLength(0);

      // Instead the internal container must have a docker-bridge edge whose target is the docker-net gateway
      const toGateway = dbEdges.filter(
        e => e.data.source === String(internalContainer.id) && e.data.target === String(netAGateway.id),
      );
      expect(toGateway).toHaveLength(1);
    });

    it('(c) docker-net gateway device itself gets a docker-bridge edge to the pivot', () => {
      const devices = [pivot, netAGateway];
      const edges = buildGatewayEdges(devices);
      const dbEdges = edges.filter(e => e.data.kind === 'docker-bridge');

      const gatewayToPivot = dbEdges.filter(
        e => e.data.source === String(pivot.id) && e.data.target === String(netAGateway.id),
      );
      expect(gatewayToPivot).toHaveLength(1);
    });

    it('(d) AC3 invariant: pivot-incident docker-bridge count == published + K gateways; internal containers are not pivot-incident', () => {
      // 2 published containers (in net_a and net_b)
      // 3 internal containers (2 in net_a, 1 in net_b)
      // 2 networks (net_a: 172.18.0/24, net_b: 172.19.0/24)
      // Expected pivot-incident docker-bridge edges: 2 (published) + 2 (gateways) = 4, NOT 2+3=5
      // Change 1 adds published→gateway edges but those are NOT pivot-incident (source is the container,
      // not the pivot), so this count must still be 4.

      const netBGateway = makeDevice(5, '172.19.0.1', 'DOCKER_BRIDGE', 'docker-net:net_b', false);
      const publishedInNetA = makeDevice(6, '172.18.0.10', 'DOCKER_BRIDGE', null, true);
      const publishedInNetB = makeDevice(7, '172.19.0.10', 'DOCKER_BRIDGE', null, true);
      const internalInNetA1 = makeDevice(8, '172.18.0.11', 'DOCKER_BRIDGE', null, false);
      const internalInNetA2 = makeDevice(9, '172.18.0.12', 'DOCKER_BRIDGE', null, false);
      const internalInNetB1 = makeDevice(10, '172.19.0.11', 'DOCKER_BRIDGE', null, false);

      const devices = [
        pivot,
        netAGateway, netBGateway,
        publishedInNetA, publishedInNetB,
        internalInNetA1, internalInNetA2, internalInNetB1,
      ];

      const edges = buildGatewayEdges(devices);
      const dbEdges = edges.filter(e => e.data.kind === 'docker-bridge');

      // Only edges whose SOURCE is the pivot count as "pivot-incident"
      const pivotIncident = dbEdges.filter(e => e.data.source === String(pivot.id));

      // published count = 2, K = 2 networks → expected 4, not 5 (N+M)
      expect(pivotIncident).toHaveLength(4);

      // Sanity: internal containers must NOT be direct targets of the pivot
      const internalIds = [
        String(internalInNetA1.id),
        String(internalInNetA2.id),
        String(internalInNetB1.id),
      ];
      for (const iid of internalIds) {
        expect(pivotIncident.map(e => e.data.target)).not.toContain(iid);
      }
    });

    it('(e) localStorage pivot override still routes docker-bridge edges from the overridden IP', () => {
      // Re-confirm the localStorage override path works with publishesHostPort fixtures
      localStorage.setItem('castellum.topology.docker-host-ip', '192.168.68.99');
      try {
        const overridePivot = makeDevice(20, '192.168.68.99', 'HOME', null, false);
        const gwDevice = makeDevice(21, '172.18.0.1', 'DOCKER_BRIDGE', 'docker-net:mynet', false);
        const pubContainer = makeDevice(22, '172.18.0.5', 'DOCKER_BRIDGE', null, true);

        const devices = [overridePivot, gwDevice, pubContainer];
        const edges = buildGatewayEdges(devices);
        const dbEdges = edges.filter(e => e.data.kind === 'docker-bridge');

        // Published container → direct edge from overridden pivot
        const fromOverridePivot = dbEdges.filter(e => e.data.source === String(overridePivot.id));
        expect(fromOverridePivot.length).toBeGreaterThan(0);

        // Specifically the published container target must be among pivot-sourced edges
        const toPub = fromOverridePivot.filter(e => e.data.target === String(pubContainer.id));
        expect(toPub).toHaveLength(1);
      } finally {
        localStorage.removeItem('castellum.topology.docker-host-ip');
      }
    });

    // ── RECONCILED (f): Change 2 — unattached internal container gets ZERO edges ──
    // Old contract: internal container whose /24 has no docker-net gateway → fallback docker-bridge
    //               edge to the pivot (anti-orphan).
    // New contract (Change 2): that scenario is "unattached" → NO edges whatsoever.
    it('(f) internal-only container with no docker-net gateway in /24 gets NO edges (unattached = disconnected)', () => {
      // An internal-only container (DOCKER_BRIDGE, publishesHostPort:false, not a gateway)
      // whose /24 contains NO docker-net gateway device.
      // New contract: no docker-bridge edge to the pivot, no isolated self-edge.
      const pivotDevice = makeDevice(1, '192.168.68.51', 'HOME', null, false);
      // Container on 172.99.0/24 — no docker-net:* gateway exists on that /24
      const unattachedContainer = makeDevice(2, '172.99.0.5', 'DOCKER_BRIDGE', null, false);

      const devices = [pivotDevice, unattachedContainer];
      const edges = buildGatewayEdges(devices);
      const dbEdges = edges.filter(e => e.data.kind === 'docker-bridge');

      // Change 2: the anti-orphan fallback is removed — no docker-bridge edge to the pivot
      const fallbackEdge = dbEdges.find(
        e => e.data.target === String(unattachedContainer.id) || e.data.source === String(unattachedContainer.id),
      );
      expect(
        fallbackEdge,
        'unattached container must NOT have any docker-bridge edge (no anti-orphan fallback)',
      ).toBeUndefined();

      // No isolated self-edge either
      const isolatedEdges = edges.filter(e => e.data.kind === 'isolated');
      expect(isolatedEdges.map(e => e.data.source)).not.toContain(String(unattachedContainer.id));

      // The unattached container must appear in zero edges total
      const allEdgesForContainer = edges.filter(
        e =>
          e.data.source === String(unattachedContainer.id) ||
          e.data.target === String(unattachedContainer.id),
      );
      expect(
        allEdgesForContainer,
        'unattached docker container must have zero edges total',
      ).toHaveLength(0);
    });

    it('(g) non-docker /24 groups still emit gateway and isolated kinds unchanged', () => {
      // HOME-only subnet: no docker involvement → gateway kind preserved
      const h1 = makeDevice(30, '10.0.0.1', 'HOME', null, false);
      const h2 = makeDevice(31, '10.0.0.50', 'HOME', null, false);
      // LINK_LOCAL singleton → isolated kind preserved
      const ll = makeDevice(32, '169.254.100.5', 'LINK_LOCAL', null, false);

      const devices = [h1, h2, ll];
      const edges = buildGatewayEdges(devices);

      const gatewayEdges = edges.filter(e => e.data.kind === 'gateway');
      expect(gatewayEdges).toHaveLength(1);
      expect(gatewayEdges[0].data.target).toBe(String(h1.id)); // .1 wins

      const isolatedEdges = edges.filter(e => e.data.kind === 'isolated');
      expect(isolatedEdges).toHaveLength(1);
      expect(isolatedEdges[0].data.source).toBe(String(ll.id));

      // No docker-bridge edges at all (no DOCKER_BRIDGE scope devices)
      expect(edges.filter(e => e.data.kind === 'docker-bridge')).toHaveLength(0);
    });

    // ────────────────────────────────────────────────────────────────────────
    // Change 1 — group hub wiring: all containers in a network connect to their gateway
    // ────────────────────────────────────────────────────────────────────────

    it('change1: every container in a network (published + internal) is wired to its docker-net gateway', () => {
      // net_a: gateway=2(172.18.0.1), published=3(172.18.0.5), internal=4(172.18.0.6)
      // All three are in the 172.18.0/24; the gateway is the hub.
      // Expected docker-bridge edges:
      //   pivot→gateway (gateway wired to pivot)
      //   published→gateway (Change 1: published also wired to hub)
      //   internal→gateway (unchanged: internal wired to hub)
      //   pivot→published (Change 1: published ALSO wired to pivot directly)
      const devices = [pivot, netAGateway, publishedContainer, internalContainer];
      const edges = buildGatewayEdges(devices);
      const dbEdges = edges.filter(e => e.data.kind === 'docker-bridge');

      // published→gateway edge must exist (Change 1)
      const publishedToGateway = dbEdges.filter(
        e =>
          e.data.source === String(publishedContainer.id) &&
          e.data.target === String(netAGateway.id),
      );
      expect(
        publishedToGateway,
        'published container must have docker-bridge edge to its docker-net gateway (Change 1)',
      ).toHaveLength(1);

      // internal→gateway edge must exist (unchanged)
      const internalToGateway = dbEdges.filter(
        e =>
          e.data.source === String(internalContainer.id) &&
          e.data.target === String(netAGateway.id),
      );
      expect(
        internalToGateway,
        'internal container must have docker-bridge edge to its docker-net gateway',
      ).toHaveLength(1);

      // pivot→published edge must still exist (published keeps direct pivot link)
      const pivotToPublished = dbEdges.filter(
        e =>
          e.data.source === String(pivot.id) &&
          e.data.target === String(publishedContainer.id),
      );
      expect(
        pivotToPublished,
        'published container must keep its direct docker-bridge edge to the host pivot',
      ).toHaveLength(1);

      // pivot→gateway edge must exist (gateway wired to pivot, unchanged)
      const pivotToGateway = dbEdges.filter(
        e =>
          e.data.source === String(pivot.id) &&
          e.data.target === String(netAGateway.id),
      );
      expect(
        pivotToGateway,
        'docker-net gateway must keep its docker-bridge edge to the host pivot',
      ).toHaveLength(1);
    });

    it('change1: published container in gatewayed network has both pivot and gateway docker-bridge edges', () => {
      // Minimal fixture: pivot + one gateway + one published container (all in same /24)
      const devices = [pivot, netAGateway, publishedContainer];
      const edges = buildGatewayEdges(devices);
      const dbEdges = edges.filter(e => e.data.kind === 'docker-bridge');

      // Both edges must exist for the published container
      const pivotToPublished = dbEdges.filter(
        e =>
          e.data.source === String(pivot.id) &&
          e.data.target === String(publishedContainer.id),
      );
      expect(pivotToPublished).toHaveLength(1);

      const publishedToGateway = dbEdges.filter(
        e =>
          e.data.source === String(publishedContainer.id) &&
          e.data.target === String(netAGateway.id),
      );
      expect(
        publishedToGateway,
        'published container must also have a docker-bridge edge to the docker-net gateway (Change 1)',
      ).toHaveLength(1);
    });

    it('change1: AC3 invariant is preserved — new published→gateway edges are not pivot-incident', () => {
      // With Change 1, a published container emits an extra docker-bridge edge (→ gateway).
      // That edge is sourced from the container, NOT from the pivot, so it must NOT
      // inflate the pivot-incident count.
      const devices = [pivot, netAGateway, publishedContainer, internalContainer];
      const edges = buildGatewayEdges(devices);
      const dbEdges = edges.filter(e => e.data.kind === 'docker-bridge');

      // Pivot-incident = edges whose source is the pivot
      const pivotIncident = dbEdges.filter(e => e.data.source === String(pivot.id));

      // K=1 gateway + 1 published → 2 pivot-incident edges
      // The extra published→gateway edge (Change 1) must NOT appear here
      expect(
        pivotIncident,
        'pivot-incident count must be 2 (1 gateway + 1 published), not inflated by published→gateway edges',
      ).toHaveLength(2);

      // The internal container must NOT be a pivot-incident target
      expect(pivotIncident.map(e => e.data.target)).not.toContain(String(internalContainer.id));
    });

    // ────────────────────────────────────────────────────────────────────────
    // Change 2 — unattached nodes fully disconnected (no pivot fallback, no peer edges)
    // ────────────────────────────────────────────────────────────────────────

    it('change2: single unattached DOCKER_BRIDGE device (no docker-net gateway in /24) gets zero edges', () => {
      // A DOCKER_BRIDGE device that is not a gateway and whose /24 has no docker-net gateway.
      // Old behaviour: anti-orphan fallback → docker-bridge edge to pivot.
      // New behaviour (Change 2): ZERO edges — fully disconnected node.
      const pivotDevice = makeDevice(50, '192.168.68.51', 'HOME', null, false);
      const unattached = makeDevice(51, '172.20.0.5', 'DOCKER_BRIDGE', null, false);
      // No docker-net:* gateway on 172.20.0/24

      const devices = [pivotDevice, unattached];
      const edges = buildGatewayEdges(devices);

      const allEdgesForUnattached = edges.filter(
        e =>
          e.data.source === String(unattached.id) ||
          e.data.target === String(unattached.id),
      );
      expect(
        allEdgesForUnattached,
        'unattached DOCKER_BRIDGE device with no gateway in its /24 must have zero edges',
      ).toHaveLength(0);
    });

    it('change2: two unattached DOCKER_BRIDGE devices in the same /24 get NO edges between them', () => {
      // Two DOCKER_BRIDGE devices (172.18.0.2, 172.18.0.3) share a /24 but have no
      // docker-net:* gateway device.  They are unattached.
      // Old behaviour: a 'gateway'-kind edge was emitted between them (peer→lowest-IP).
      // New behaviour (Change 2): NO edge between them whatsoever.
      const pivotDevice = makeDevice(37, '192.168.68.51', 'HOME', null, false);
      const unattached1 = makeDevice(38, '172.18.0.2', 'DOCKER_BRIDGE', null, false);
      const unattached2 = makeDevice(39, '172.18.0.3', 'DOCKER_BRIDGE', null, false);
      // No docker-net:* gateway on 172.18.0/24

      const devices = [pivotDevice, unattached1, unattached2];
      const edges = buildGatewayEdges(devices);

      // No gateway-kind edge between the two unattached devices
      const peerEdge = edges.find(
        e =>
          (e.data.source === String(unattached1.id) || e.data.target === String(unattached1.id)) &&
          (e.data.source === String(unattached2.id) || e.data.target === String(unattached2.id)),
      );
      expect(
        peerEdge,
        'two unattached DOCKER_BRIDGE devices in the same /24 must NOT have an edge between them (Change 2)',
      ).toBeUndefined();

      // Neither device must appear in any edge at all
      const allEdgesFor1 = edges.filter(
        e => e.data.source === String(unattached1.id) || e.data.target === String(unattached1.id),
      );
      const allEdgesFor2 = edges.filter(
        e => e.data.source === String(unattached2.id) || e.data.target === String(unattached2.id),
      );
      expect(allEdgesFor1, 'unattached device 1 must have zero edges total').toHaveLength(0);
      expect(allEdgesFor2, 'unattached device 2 must have zero edges total').toHaveLength(0);
    });

    it('change2: no isolated self-edge for unattached DOCKER_BRIDGE device', () => {
      // An unattached DOCKER_BRIDGE device must NOT receive a synthetic isolated self-edge
      // — it should simply have zero edges (fully disconnected from the graph).
      const pivotDevice = makeDevice(60, '192.168.68.51', 'HOME', null, false);
      const unattached = makeDevice(61, '172.21.0.7', 'DOCKER_BRIDGE', null, false);

      const devices = [pivotDevice, unattached];
      const edges = buildGatewayEdges(devices);

      const isolatedEdges = edges.filter(e => e.data.kind === 'isolated');
      expect(isolatedEdges.map(e => e.data.source)).not.toContain(String(unattached.id));

      // Confirm truly zero edges for this device
      const allEdgesForUnattached = edges.filter(
        e => e.data.source === String(unattached.id) || e.data.target === String(unattached.id),
      );
      expect(allEdgesForUnattached).toHaveLength(0);
    });
  });
});
