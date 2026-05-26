import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { DeviceDetailPanel } from '../components/DeviceDetailPanel';
import type { Device, DeviceRiskDto, NetworkService } from '../api/types';

const device: Device = {
  id: 1,
  ipAddress: '192.168.1.10',
  hostname: 'demo-1',
  macAddress: 'aa:bb:cc:dd:ee:ff',
  firstSeen: null,
  lastSeen: null,
  criticality: 'HIGH',
  discoveryScope: 'DOCKER_BRIDGE',
  lastSeenIface: null,
};

const risk: DeviceRiskDto = {
  deviceId: 1,
  score: '7.50',
  topCveIds: ['CVE-2020-15778', 'CVE-2020-14145'],
};

const services: NetworkService[] = [
  { id: 1, deviceId: 1, port: 22, protocol: 'tcp', name: 'openssh', version: '8.2',
    observedAt: null, vendor: null, product: null, protocolFamily: null },
  { id: 2, deviceId: 1, port: 80, protocol: 'tcp', name: 'nginx', version: '1.18',
    observedAt: null, vendor: null, product: null, protocolFamily: null },
];

describe('<DeviceDetailPanel />', () => {
  it('renders nothing when device is null', () => {
    const { container } = render(
      <DeviceDetailPanel device={null} risk={null} services={[]} onClose={() => {}} />
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('shows device + risk + service rows + top CVEs', () => {
    render(
      <DeviceDetailPanel device={device} risk={risk} services={services} onClose={() => {}} />
    );
    // 'demo-1' appears both in the header <h2> and in the hostname read-only span;
    // assert the header copy specifically.
    expect(screen.getByRole('heading', { level: 2, name: 'demo-1' })).toBeInTheDocument();
    expect(screen.getByText('7.50')).toBeInTheDocument();
    expect(screen.getByText('22')).toBeInTheDocument();
    expect(screen.getByText('openssh')).toBeInTheDocument();
    expect(screen.getByText('nginx')).toBeInTheDocument();
    expect(screen.getByText('CVE-2020-15778')).toBeInTheDocument();
  });

  it('calls onClose when close button is clicked', () => {
    const handleClose = vi.fn();
    render(
      <DeviceDetailPanel device={device} risk={risk} services={services} onClose={handleClose} />
    );
    fireEvent.click(screen.getByLabelText('Close panel'));
    expect(handleClose).toHaveBeenCalledTimes(1);
  });

  it('renders dash when risk.score is NaN', () => {
    const nanRisk: DeviceRiskDto = { deviceId: 1, score: 'not-a-number', topCveIds: [] };
    const { container } = render(
      <DeviceDetailPanel device={device} risk={nanRisk} services={[]} onClose={() => {}} />
    );
    // Score badge carries text-2xl font-bold; match the dash there specifically
    // (the device dl also contains '—' for missing mac/firstSeen/lastSeen).
    const scoreBadge = container.querySelector('span.text-2xl');
    expect(scoreBadge).not.toBeNull();
    expect(scoreBadge?.textContent).toBe('—');
    expect(screen.queryByText(/NaN/)).not.toBeInTheDocument();
  });

  it('renders dash when risk.score is Infinity', () => {
    const infRisk: DeviceRiskDto = { deviceId: 1, score: 'Infinity', topCveIds: [] };
    const { container } = render(
      <DeviceDetailPanel device={device} risk={infRisk} services={[]} onClose={() => {}} />
    );
    const scoreBadge = container.querySelector('span.text-2xl');
    expect(scoreBadge).not.toBeNull();
    expect(scoreBadge?.textContent).toBe('—');
    expect(screen.queryByText(/Infinity/)).not.toBeInTheDocument();
  });

  it('VIEWER (isAdmin omitted) sees no edit affordances and no decommission button', () => {
    render(
      <DeviceDetailPanel device={device} risk={risk} services={services} onClose={() => {}} />
    );
    expect(screen.queryByRole('button', { name: /edit criticality/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /edit hostname/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^decommission$/i })).not.toBeInTheDocument();
    // Read-only criticality is still shown.
    expect(screen.getByTestId('criticality-readonly')).toHaveTextContent('HIGH');
  });

  it('ADMIN (isAdmin=true) sees edit affordances and decommission button', () => {
    render(
      <DeviceDetailPanel
        device={device}
        risk={risk}
        services={services}
        onClose={() => {}}
        isAdmin={true}
      />
    );
    expect(screen.getByRole('button', { name: /edit criticality/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /edit hostname/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^decommission$/i })).toBeInTheDocument();
  });

  it('panel_rendersScopeChipBelowHostname', () => {
    render(
      <DeviceDetailPanel device={device} risk={risk} services={services} onClose={() => {}} />
    );
    const chip = screen.getByTestId('scope-chip');
    expect(chip).toBeInTheDocument();
    expect(chip).toHaveTextContent('DOCKER_BRIDGE');
    expect(chip).toHaveStyle({ backgroundColor: 'rgb(37, 99, 235)' });
  });

  it('lastSeenIface_renders_when_present', () => {
    const ifaceDevice: Device = { ...device, lastSeenIface: 'eth0' };
    render(
      <DeviceDetailPanel device={ifaceDevice} risk={risk} services={services} onClose={() => {}} />
    );
    const dt = screen.getByText('last seen iface');
    expect(dt).toBeInTheDocument();
    // The <dd> immediately follows the <dt> in the same dl grid.
    expect(dt.nextElementSibling).toHaveTextContent('eth0');
  });

  it('lastSeenIface_omitted_when_null', () => {
    // device fixture already has lastSeenIface = null.
    render(
      <DeviceDetailPanel device={device} risk={risk} services={services} onClose={() => {}} />
    );
    expect(screen.queryByText('last seen iface')).not.toBeInTheDocument();
  });
});
