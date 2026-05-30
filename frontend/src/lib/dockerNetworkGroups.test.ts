/**
 * TDD red-phase tests for Task 2.3 (AC4):
 *
 * buildDockerNetworkGroups must handle stale/unattached DOCKER_BRIDGE devices
 * (ARP residue, e.g. 172.18.x with no running container/gateway) cleanly:
 *   - render them in a muted DOCKER_UNATTACHED_GROUP_ID group (muted-group policy)
 *   - the unattached group must carry muted: true so the renderer can style it
 *     differently from real network groups
 *   - NEVER emit an empty/orphan unattached group when no stale devices exist
 *   - NEVER crash on empty input or stale-only input
 *   - gateways / published-port containers / internal containers must NOT
 *     be mis-routed into the unattached group
 *
 * Policy decision: muted-group (DOCKER_UNATTACHED_GROUP_ID) — the constant already
 * exists in the source so we assert the group is produced (not excluded), and that
 * it is only produced when >=1 device populates it.
 *
 * FALSIFIABLE assertions (red phase):
 *   - ac4a_unattachedGroup_has_muted_true: the DockerNetworkGroup for the unattached
 *     box must carry a `muted: true` property — this field does NOT exist on the
 *     current DockerNetworkGroup interface and will fail red until the implementer
 *     adds it.
 *   - ac4b_namedNetworkGroups_do_not_have_muted_true: named network groups must NOT
 *     be flagged as muted — will fail red until `muted` is added and gated correctly.
 */

import { describe, it, expect } from 'vitest';
import type { Device, DiscoveryScope } from '../api/types';
import {
  buildDockerNetworkGroups,
  DOCKER_UNATTACHED_GROUP_ID,
  dockerNetworkGroupId,
  type DockerNetworkGroup,
} from './dockerNetworkGroups';

// ─── Fixture builder ────────────────────────────────────────────────────────

function makeDevice(
  id: number,
  ip: string,
  scope: DiscoveryScope,
  hostname: string | null = null,
  publishesHostPort = false,
): Device {
  return {
    id,
    ipAddress: ip,
    hostname,
    macAddress: null,
    firstSeen: '2026-01-01T00:00:00Z',
    lastSeen: '2026-01-01T00:00:00Z',
    criticality: 'MEDIUM',
    discoveryScope: scope,
    lastSeenIface: null,
    discoverySource: 'DOCKER' as const,
    serviceCount: 0,
    osName: null,
    osAccuracy: null,
    osCpe: null,
    publishesHostPort,
    deviceRole: 'UNKNOWN',
    originHostIp: 'local',
    originHostName: null,
    networkName: null,
  };
}

// ─── Network fixtures ───────────────────────────────────────────────────────

// Network alpha at 172.30.0.x
const GW_ALPHA     = makeDevice(10, '172.30.0.1', 'DOCKER_BRIDGE', 'docker-net:alpha_net');
// Published-port container in alpha (publishesHostPort = true)
const PUB_ALPHA    = makeDevice(11, '172.30.0.2', 'DOCKER_BRIDGE', 'alpha-pub', true);
// Internal container in alpha (publishesHostPort = false)
const INT_ALPHA    = makeDevice(12, '172.30.0.3', 'DOCKER_BRIDGE', 'alpha-int', false);

// Network beta at 172.31.0.x
const GW_BETA      = makeDevice(20, '172.31.0.1', 'DOCKER_BRIDGE', 'docker-net:beta_net');
const INT_BETA     = makeDevice(21, '172.31.0.2', 'DOCKER_BRIDGE', 'beta-svc', false);

// Stale/unattached ARP entries — 172.18.x with NO corresponding gateway
const STALE_1      = makeDevice(30, '172.18.0.5', 'DOCKER_BRIDGE', null);
const STALE_2      = makeDevice(31, '172.18.0.6', 'DOCKER_BRIDGE', 'leftover-container');

const GROUP_ID_ALPHA = dockerNetworkGroupId('alpha_net');
const GROUP_ID_BETA  = dockerNetworkGroupId('beta_net');

// ─── AC4 (a): stale DOCKER_BRIDGE device → DOCKER_UNATTACHED_GROUP_ID ───────

describe('AC4 (a): stale/unattached device handling', () => {
  it('ac4a_staleDevice_appearsIn_unattachedGroup', () => {
    // A DOCKER_BRIDGE device with no matching gateway/network must land in
    // DOCKER_UNATTACHED_GROUP_ID (muted-group policy).
    const devices: Device[] = [GW_ALPHA, INT_ALPHA, STALE_1];
    const groups = buildDockerNetworkGroups(devices);

    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID);
    expect(unattached, 'unattached group must be produced when a stale device exists').toBeTruthy();
    expect(unattached!.memberIds.has(30)).toBe(true);
  });

  it('ac4a_unattachedGroup_label_is_non-empty_and_descriptive', () => {
    // The group must have a human-readable, non-empty label — not blank or
    // the raw group id.
    const devices: Device[] = [GW_ALPHA, STALE_1];
    const groups = buildDockerNetworkGroups(devices);

    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID);
    expect(unattached).toBeTruthy();
    expect(unattached!.label.trim().length).toBeGreaterThan(0);
    // Must not be the raw group id string — it should be human-readable
    expect(unattached!.label).not.toBe(DOCKER_UNATTACHED_GROUP_ID);
  });

  it('ac4a_unattachedGroup_has_muted_true', () => {
    // The DockerNetworkGroup for the unattached box must carry muted: true so the
    // TopologyView renderer can apply a distinct muted visual style to it.
    // THIS IS A RED-PHASE ASSERTION: the DockerNetworkGroup interface does not yet
    // carry a `muted` field — the implementer must add it.
    const devices: Device[] = [GW_ALPHA, STALE_1];
    const groups = buildDockerNetworkGroups(devices);

    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID) as
      | (DockerNetworkGroup & { muted?: boolean })
      | undefined;
    expect(unattached).toBeTruthy();
    expect(
      (unattached as unknown as Record<string, unknown>)['muted'],
      'unattached group must carry muted: true',
    ).toBe(true);
  });

  it('ac4a_multipleStaleDevices_allInUnattachedGroup', () => {
    // Multiple stale ARP entries must all land in the same unattached group.
    const devices: Device[] = [GW_ALPHA, STALE_1, STALE_2];
    const groups = buildDockerNetworkGroups(devices);

    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID);
    expect(unattached).toBeTruthy();
    expect(unattached!.memberIds.has(30)).toBe(true);
    expect(unattached!.memberIds.has(31)).toBe(true);
  });

  it('ac4a_namedNetworkGroups_do_not_have_muted_true', () => {
    // Named network groups (real docker networks) must NOT be flagged as muted.
    // This will also fail red until `muted` is added and gated correctly.
    const devices: Device[] = [GW_ALPHA, INT_ALPHA, GW_BETA, INT_BETA, STALE_1];
    const groups = buildDockerNetworkGroups(devices);

    const namedGroups = groups.filter(g => g.groupId !== DOCKER_UNATTACHED_GROUP_ID);
    expect(namedGroups.length).toBeGreaterThan(0);
    for (const g of namedGroups) {
      const muted = (g as unknown as Record<string, unknown>)['muted'];
      expect(
        muted,
        `named group "${g.groupId}" must not have muted=true`,
      ).not.toBe(true);
    }
  });
});

// ─── AC4 (b): no unattached group when no stale devices ─────────────────────

describe('AC4 (b): no unattached group emitted when zero stale devices', () => {
  it('ac4b_noStaleDevices_noUnattachedGroup_emitted', () => {
    // When every DOCKER_BRIDGE device has a matching gateway, there must be NO
    // unattached group in the output — no empty/orphan compound parent.
    const devices: Device[] = [GW_ALPHA, PUB_ALPHA, INT_ALPHA, GW_BETA, INT_BETA];
    const groups = buildDockerNetworkGroups(devices);

    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID);
    expect(
      unattached,
      'must NOT emit an unattached group when all devices have a matching network',
    ).toBeUndefined();
  });

  it('ac4b_onlyGateways_noUnattachedGroup_emitted', () => {
    // Gateway-only (no containers, no stale) → no unattached group.
    const devices: Device[] = [GW_ALPHA, GW_BETA];
    const groups = buildDockerNetworkGroups(devices);

    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID);
    expect(unattached).toBeUndefined();
  });

  it('ac4b_noUnattachedGroup_means_no_empty_memberIds', () => {
    // Broad invariant: every group returned must have at least one member.
    const devices: Device[] = [GW_ALPHA, PUB_ALPHA, INT_ALPHA, GW_BETA, INT_BETA];
    const groups = buildDockerNetworkGroups(devices);

    for (const g of groups) {
      expect(
        g.memberIds.size,
        `group ${g.groupId} must have at least one member`,
      ).toBeGreaterThan(0);
    }
  });
});

// ─── AC4 (c): gateway placed in its network group, never in unattached ───────

describe('AC4 (c): gateway never mis-routed to unattached group', () => {
  it('ac4c_gateway_isInItsOwnNetworkGroup_notUnattached', () => {
    // A docker-net:<name> gateway must be in its own network group, not unattached.
    const devices: Device[] = [GW_ALPHA, STALE_1];
    const groups = buildDockerNetworkGroups(devices);

    const alphaGroup = groups.find(g => g.groupId === GROUP_ID_ALPHA);
    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID);

    // Gateway is in alpha group
    expect(alphaGroup).toBeTruthy();
    expect(alphaGroup!.memberIds.has(10)).toBe(true);

    // Gateway must NOT appear in unattached group (if it exists)
    if (unattached) {
      expect(unattached.memberIds.has(10)).toBe(false);
    }
  });

  it('ac4c_gateway_not_in_unattached_even_when_stale_devices_present', () => {
    // Regression: with stale devices present the unattached group is created;
    // gateways must still not leak into it.
    const devices: Device[] = [GW_ALPHA, GW_BETA, STALE_1, STALE_2];
    const groups = buildDockerNetworkGroups(devices);

    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID);
    expect(unattached).toBeTruthy(); // stale devices exist → group is produced

    // Neither gateway must be in unattached
    expect(unattached!.memberIds.has(GW_ALPHA.id)).toBe(false);
    expect(unattached!.memberIds.has(GW_BETA.id)).toBe(false);
  });
});

// ─── AC4 (d): published-port + internal containers land in their network group

describe('AC4 (d): published-port and internal containers routed to their network group', () => {
  it('ac4d_publishedPortContainer_landsInNetworkGroup_notUnattached', () => {
    // A container with publishesHostPort=true must join its /24 network group.
    const devices: Device[] = [GW_ALPHA, PUB_ALPHA, STALE_1];
    const groups = buildDockerNetworkGroups(devices);

    const alphaGroup = groups.find(g => g.groupId === GROUP_ID_ALPHA);
    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID);

    expect(alphaGroup).toBeTruthy();
    expect(alphaGroup!.memberIds.has(PUB_ALPHA.id)).toBe(true);

    // Published-port container must NOT be in unattached
    if (unattached) {
      expect(unattached.memberIds.has(PUB_ALPHA.id)).toBe(false);
    }
  });

  it('ac4d_internalContainer_landsInNetworkGroup_notUnattached', () => {
    // A container with publishesHostPort=false must join its /24 network group.
    const devices: Device[] = [GW_ALPHA, INT_ALPHA, STALE_1];
    const groups = buildDockerNetworkGroups(devices);

    const alphaGroup = groups.find(g => g.groupId === GROUP_ID_ALPHA);
    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID);

    expect(alphaGroup).toBeTruthy();
    expect(alphaGroup!.memberIds.has(INT_ALPHA.id)).toBe(true);

    if (unattached) {
      expect(unattached.memberIds.has(INT_ALPHA.id)).toBe(false);
    }
  });

  it('ac4d_bothContainerTypes_in_same_network_correctly_grouped', () => {
    // Published AND internal containers sharing the same /24 both land in
    // the same network group, never in unattached.
    const devices: Device[] = [GW_ALPHA, PUB_ALPHA, INT_ALPHA, GW_BETA, STALE_1];
    const groups = buildDockerNetworkGroups(devices);

    const alphaGroup = groups.find(g => g.groupId === GROUP_ID_ALPHA);
    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID);

    expect(alphaGroup).toBeTruthy();
    expect(alphaGroup!.memberIds.has(PUB_ALPHA.id)).toBe(true);
    expect(alphaGroup!.memberIds.has(INT_ALPHA.id)).toBe(true);
    // Neither should bleed into unattached
    if (unattached) {
      expect(unattached.memberIds.has(PUB_ALPHA.id)).toBe(false);
      expect(unattached.memberIds.has(INT_ALPHA.id)).toBe(false);
    }
  });

  it('ac4d_containersInNetworkX_notPresentInNetworkY', () => {
    // Cross-contamination guard: alpha containers must never appear in beta group.
    const devices: Device[] = [GW_ALPHA, PUB_ALPHA, INT_ALPHA, GW_BETA, INT_BETA];
    const groups = buildDockerNetworkGroups(devices);

    const alphaGroup = groups.find(g => g.groupId === GROUP_ID_ALPHA)!;
    const betaGroup  = groups.find(g => g.groupId === GROUP_ID_BETA)!;

    // Alpha containers not in beta
    expect(betaGroup.memberIds.has(PUB_ALPHA.id)).toBe(false);
    expect(betaGroup.memberIds.has(INT_ALPHA.id)).toBe(false);
    // Beta container not in alpha
    expect(alphaGroup.memberIds.has(INT_BETA.id)).toBe(false);
  });
});

// ─── AC4 (e): no throw on empty or stale-only input ─────────────────────────

describe('AC4 (e): no crash on degenerate inputs', () => {
  it('ac4e_emptyDeviceList_returnsEmptyArray_noCrash', () => {
    expect(() => buildDockerNetworkGroups([])).not.toThrow();
    const result = buildDockerNetworkGroups([]);
    expect(Array.isArray(result)).toBe(true);
    expect(result).toHaveLength(0);
  });

  it('ac4e_staleOnlyList_returnsUnattachedGroup_noCrash', () => {
    // Only stale ARP rows — no gateways at all.
    const devices: Device[] = [STALE_1, STALE_2];
    expect(() => buildDockerNetworkGroups(devices)).not.toThrow();

    const groups = buildDockerNetworkGroups(devices);
    // All stale → unattached group (muted-group policy), no named network groups
    expect(groups.length).toBe(1);
    expect(groups[0].groupId).toBe(DOCKER_UNATTACHED_GROUP_ID);
    expect(groups[0].memberIds.has(STALE_1.id)).toBe(true);
    expect(groups[0].memberIds.has(STALE_2.id)).toBe(true);
  });

  it('ac4e_staleOnlyList_unattachedGroup_hasNonEmptyLabel', () => {
    // Even with stale-only input the group must carry a readable label.
    const groups = buildDockerNetworkGroups([STALE_1]);
    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID);
    expect(unattached).toBeTruthy();
    expect(unattached!.label.trim().length).toBeGreaterThan(0);
  });

  it('ac4e_nonDockerDevicesInList_noThrow_noCrash', () => {
    // A mix of non-DOCKER_BRIDGE scopes mixed with stale DOCKER_BRIDGE rows
    // must not cause any crash.
    const nonDocker = makeDevice(99, '192.168.1.1', 'HOME', null);
    const devices: Device[] = [nonDocker, STALE_1];
    expect(() => buildDockerNetworkGroups(devices)).not.toThrow();
    const groups = buildDockerNetworkGroups(devices);
    // HOME device must NOT appear in any group (only DOCKER_BRIDGE scope is grouped)
    for (const g of groups) {
      expect(g.memberIds.has(99)).toBe(false);
    }
  });

  it('ac4e_gatewayWithNullIp_doesNotCrash', () => {
    // Edge: a gateway device whose ipAddress yields null from ipv4Slash24 must
    // be skipped gracefully, not crash.
    const badGw = makeDevice(50, '', 'DOCKER_BRIDGE', 'docker-net:bad_net');
    expect(() => buildDockerNetworkGroups([badGw, STALE_1])).not.toThrow();
  });
});

// ─── Invariant: returned groups always have memberIds.size > 0 ───────────────

describe('Invariant: no empty group objects ever returned', () => {
  it('invariant_allGroups_haveAtLeastOneMember', () => {
    // Run with a variety of inputs and assert the invariant holds universally.
    const inputs: Device[][] = [
      [],
      [STALE_1],
      [GW_ALPHA],
      [GW_ALPHA, PUB_ALPHA, INT_ALPHA],
      [GW_ALPHA, STALE_1],
      [GW_ALPHA, GW_BETA, STALE_1, STALE_2],
      [GW_ALPHA, PUB_ALPHA, INT_ALPHA, GW_BETA, INT_BETA, STALE_1],
    ];
    for (const input of inputs) {
      const groups = buildDockerNetworkGroups(input);
      for (const g of groups) {
        expect(
          g.memberIds.size,
          `group "${g.groupId}" must have ≥1 member for input length ${input.length}`,
        ).toBeGreaterThan(0);
      }
    }
  });

  it('invariant_unattachedGroup_only_when_populated', () => {
    // The unattached group must ONLY appear when it has at least one member.
    const noStaleInput: Device[] = [GW_ALPHA, PUB_ALPHA, INT_ALPHA];
    const groups = buildDockerNetworkGroups(noStaleInput);
    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID);
    // If it's present, it must be populated
    if (unattached !== undefined) {
      expect(unattached.memberIds.size).toBeGreaterThan(0);
    }
    // In this specific case it must NOT be present at all
    expect(unattached).toBeUndefined();
  });
});

// ─── Task 3.2: group-by-networkName + bridge(default) label ─────────────────

describe('Task 3.2: group-by-networkName + bridge(default)', () => {
  /**
   * NO-OP invariant (HARD): containers with networkName matching their /24's
   * gateway produce identical groupIds and memberSets as the /24-inference path.
   * Simulate current data: container at 172.30.0.2 with networkName="alpha_net",
   * gateway at 172.30.0.1 with hostname "docker-net:alpha_net".
   */
  it('groupByNetworkName_noOp_identicalToSlash24Inference', () => {
    // Containers carrying networkName matching their gateway's network name.
    const gwAlpha = { ...GW_ALPHA };                           // gateway, networkName=null
    const c1 = { ...PUB_ALPHA, networkName: 'alpha_net' };    // container with networkName set
    const c2 = { ...INT_ALPHA, networkName: 'alpha_net' };

    const gwBeta = { ...GW_BETA };
    const c3 = { ...INT_BETA, networkName: 'beta_net' };

    const groups = buildDockerNetworkGroups([gwAlpha, c1, c2, gwBeta, c3]);

    // Baseline (legacy /24): same devices without networkName
    const c1Legacy = { ...PUB_ALPHA, networkName: null };
    const c2Legacy = { ...INT_ALPHA, networkName: null };
    const c3Legacy = { ...INT_BETA,  networkName: null };
    const groupsLegacy = buildDockerNetworkGroups([gwAlpha, c1Legacy, c2Legacy, gwBeta, c3Legacy]);

    // GroupIds must match
    const groupIds     = new Set(groups.map(g => g.groupId));
    const groupIdsLegacy = new Set(groupsLegacy.map(g => g.groupId));
    expect(groupIds).toEqual(groupIdsLegacy);

    // MemberSets must match for each groupId
    for (const g of groups) {
      const lgacy = groupsLegacy.find(gl => gl.groupId === g.groupId);
      expect(lgacy).toBeDefined();
      expect(g.memberIds).toEqual(lgacy!.memberIds);
    }
  });

  /**
   * bridge(default) label: a container on the raw "bridge" network renders
   * label === 'bridge (default)' while groupId === 'docker-net-group-bridge'.
   */
  it('bridgeNetwork_displayLabel_bridgeDefault_groupIdUnchanged', () => {
    const gwBridge = makeDevice(50, '172.17.0.1', 'DOCKER_BRIDGE', 'docker-net:bridge');
    const container = { ...makeDevice(51, '172.17.0.2', 'DOCKER_BRIDGE', 'my-container'), networkName: 'bridge' };

    const groups = buildDockerNetworkGroups([gwBridge, container]);

    const bridgeGroup = groups.find(g => g.groupId === dockerNetworkGroupId('bridge'));
    expect(bridgeGroup).toBeDefined();
    expect(bridgeGroup!.label).toBe('bridge (default)');
    expect(bridgeGroup!.groupId).toBe('docker-net-group-bridge');
  });

  /**
   * Null fallback: a DOCKER_BRIDGE device with networkName === null still groups
   * via the /24 + gateway path (legacy behaviour preserved).
   */
  it('nullNetworkName_fallsBackTo_slash24Inference', () => {
    const gw = makeDevice(60, '172.40.0.1', 'DOCKER_BRIDGE', 'docker-net:mynet');
    const containerWithNull = makeDevice(61, '172.40.0.2', 'DOCKER_BRIDGE', 'no-name-container');
    // containerWithNull has networkName=null (from makeDevice default)

    const groups = buildDockerNetworkGroups([gw, containerWithNull]);

    // Must land in mynet group (via /24 fallback), not unattached
    const mynetGroup = groups.find(g => g.groupId === dockerNetworkGroupId('mynet'));
    expect(mynetGroup).toBeDefined();
    expect(mynetGroup!.memberIds.has(containerWithNull.id)).toBe(true);

    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID);
    expect(unattached).toBeUndefined();
  });

  /**
   * Device with neither networkName nor matching gateway → unattached group.
   */
  it('noNetworkName_noMatchingGateway_goesToUnattachedGroup', () => {
    const stale = makeDevice(70, '172.99.0.5', 'DOCKER_BRIDGE', null); // networkName=null, no gateway
    const groups = buildDockerNetworkGroups([stale]);

    const unattached = groups.find(g => g.groupId === DOCKER_UNATTACHED_GROUP_ID);
    expect(unattached).toBeDefined();
    expect(unattached!.memberIds.has(stale.id)).toBe(true);
  });
});
