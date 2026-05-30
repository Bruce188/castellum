/**
 * Contract pin for the DeviceRole union and Device.deviceRole field.
 * The real verifier is `tsc -b`; this test pins the shape in the suite
 * so a future field rename is caught at test time too.
 */

import { describe, it, expect } from 'vitest';
import type { DeviceRole, Device } from '../api/types';

describe('DeviceRole type contract', () => {
  it('DeviceRole union accepts all six backend values', () => {
    const roles: DeviceRole[] = ['LAPTOP', 'DESKTOP', 'SERVER', 'ROUTER', 'CONTAINER', 'UNKNOWN'];
    expect(roles).toHaveLength(6);
  });

  it('Device interface includes deviceRole field', () => {
    const r: DeviceRole = 'CONTAINER';
    const d: Device = {
      id: 1,
      ipAddress: '10.0.0.1',
      hostname: null,
      macAddress: null,
      firstSeen: null,
      lastSeen: null,
      criticality: 'MEDIUM',
      discoveryScope: 'HOME',
      lastSeenIface: null,
      discoverySource: null,
      serviceCount: 0,
      osName: null,
      osAccuracy: null,
      osCpe: null,
      publishesHostPort: false,
      deviceRole: 'UNKNOWN',
      originHostIp: 'local',
      originHostName: null,
      networkName: null,
    };
    expect(r).toBe('CONTAINER');
    expect(d.deviceRole).toBe('UNKNOWN');
  });
});
