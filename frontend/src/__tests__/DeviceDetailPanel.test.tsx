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
    expect(screen.getByText('demo-1')).toBeInTheDocument();
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
});
