import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { DeviceDetailPanel } from '../components/DeviceDetailPanel';
import type { Device } from '../api/types';

const PLACEHOLDER = 'mac:aa-bb-cc-dd-ee-ff';

function makePlaceholderDevice(hostname: string | null): Device {
  return {
    id: 9,
    ipAddress: PLACEHOLDER,
    hostname,
    macAddress: 'aa:bb:cc:dd:ee:ff',
    firstSeen: null,
    lastSeen: null,
    criticality: 'LOW',
    discoveryScope: 'HOME',
    lastSeenIface: 'eth0',
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
}

describe('<DeviceDetailPanel /> MAC-placeholder IP rendering', () => {
  it('renders "no IP" in the IP sub-line for a placeholder device with a hostname', () => {
    render(
      <DeviceDetailPanel
        device={makePlaceholderDevice('lldp-switch')}
        risk={null}
        services={[]}
        onClose={() => {}}
      />
    );
    expect(screen.getByRole('heading', { level: 2, name: 'lldp-switch' })).toBeInTheDocument();
    expect(screen.getByText('no IP')).toBeInTheDocument();
    expect(screen.queryByText(PLACEHOLDER)).not.toBeInTheDocument();
  });

  it('renders "no IP" in the header fallback for a hostname-less placeholder device', () => {
    render(
      <DeviceDetailPanel
        device={makePlaceholderDevice(null)}
        risk={null}
        services={[]}
        onClose={() => {}}
      />
    );
    // hostname is null, so the h2 falls back to the device IP — must be "no IP", not raw.
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent('no IP');
    expect(screen.queryByText(PLACEHOLDER)).not.toBeInTheDocument();
  });
});
