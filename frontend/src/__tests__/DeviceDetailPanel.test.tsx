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
  discoverySource: null,
  serviceCount: 0,
  osName: null,
  osAccuracy: null,
  osCpe: null,
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

  // ────────────────────────────────────────────────────────────────────────
  // v3-F1 — KEV exposure chip at the top of the risk header.
  // ────────────────────────────────────────────────────────────────────────

  it('deviceDetailPanel_rendersKevExposureChip_whenComponentsKevPresentTrue', () => {
    const riskWithKev: DeviceRiskDto = {
      deviceId: 1,
      score: '7.50',
      topCveIds: [],
      components: {
        cvssMax: '7.5',
        epssMax: '0.5',
        kevPresent: true,
        criticalityWeight: '0.25',
      },
    };
    render(
      <DeviceDetailPanel device={device} risk={riskWithKev} services={[]} onClose={() => {}} />
    );
    const chip = screen.getByTestId('kev-exposure-chip');
    expect(chip).toBeInTheDocument();
    expect(chip).toHaveTextContent(/KEV exposure/i);
  });

  it('deviceDetailPanel_omitsKevExposureChip_whenComponentsKevPresentFalseOrAbsent', () => {
    // Sub-assertion A: kevPresent = false → chip absent.
    const riskKevFalse: DeviceRiskDto = {
      deviceId: 1,
      score: '7.50',
      topCveIds: [],
      components: {
        cvssMax: '7.5',
        epssMax: '0.5',
        kevPresent: false,
        criticalityWeight: '0.25',
      },
    };
    const { rerender, unmount } = render(
      <DeviceDetailPanel device={device} risk={riskKevFalse} services={[]} onClose={() => {}} />
    );
    expect(screen.queryByTestId('kev-exposure-chip')).toBeNull();

    // Sub-assertion B: components undefined → chip absent (guards the
    // risk?.components?.kevPresent optional-chain).
    const riskNoComponents: DeviceRiskDto = {
      deviceId: 1,
      score: '7.50',
      topCveIds: [],
    };
    rerender(
      <DeviceDetailPanel device={device} risk={riskNoComponents} services={[]} onClose={() => {}} />
    );
    expect(screen.queryByTestId('kev-exposure-chip')).toBeNull();
    unmount();
  });

  // ────────────────────────────────────────────────────────────────────────
  // AC3/AC4 — discoverySource "discovered via" row
  // ────────────────────────────────────────────────────────────────────────

  it('discoverySource_renders_discoveredViaRow_whenPresent', () => {
    const d: Device = { ...device, discoverySource: 'NMAP_SCAN' };
    render(
      <DeviceDetailPanel device={d} risk={risk} services={[]} onClose={() => {}} />
    );
    const dt = screen.getByText('discovered via');
    expect(dt).toBeInTheDocument();
    expect(dt.nextElementSibling).toHaveTextContent('NMAP_SCAN');
  });

  it('discoverySource_rendersUnknown_whenNull', () => {
    // device fixture has discoverySource: null
    render(
      <DeviceDetailPanel device={device} risk={risk} services={[]} onClose={() => {}} />
    );
    const dt = screen.getByText('discovered via');
    expect(dt).toBeInTheDocument();
    expect(dt.nextElementSibling).toHaveTextContent('Unknown');
  });

  // ────────────────────────────────────────────────────────────────────────
  // OS detection row — osName / osAccuracy / osCpe
  // ────────────────────────────────────────────────────────────────────────

  it('os_renders_nameAndAccuracy_whenPresent', () => {
    const d: Device = { ...device, osName: 'Linux 5.4 - 5.15', osAccuracy: 96, osCpe: 'cpe:/o:linux:linux_kernel:5' };
    render(
      <DeviceDetailPanel device={d} risk={risk} services={[]} onClose={() => {}} />
    );
    expect(screen.getByTestId('device-os')).toHaveTextContent('Linux 5.4 - 5.15 (96%)');
  });

  it('os_rendersFallback_whenNull', () => {
    // device fixture has no osName — fallback should show 'Unknown'
    render(
      <DeviceDetailPanel device={device} risk={risk} services={[]} onClose={() => {}} />
    );
    expect(screen.getByTestId('device-os')).toHaveTextContent('Unknown');
  });

  it('os_rendersNameWithoutAccuracy_whenAccuracyNull', () => {
    const d: Device = { ...device, osName: 'Linux', osAccuracy: null };
    render(
      <DeviceDetailPanel device={d} risk={risk} services={[]} onClose={() => {}} />
    );
    const osEl = screen.getByTestId('device-os');
    expect(osEl).toHaveTextContent('Linux');
    expect(osEl.textContent).not.toMatch(/\(.*%\)/);
  });
});
