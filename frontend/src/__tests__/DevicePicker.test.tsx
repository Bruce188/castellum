import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { DevicePicker } from '../components/DevicePicker';
import type { Device } from '../api/types';

const DEVICES: Device[] = [
  { id: 1, ipAddress: '10.0.0.1', hostname: 'web-prod', macAddress: null, firstSeen: null, lastSeen: null, criticality: 'HIGH', discoveryScope: 'HOME', lastSeenIface: null, discoverySource: null, serviceCount: 0, osName: null, osAccuracy: null, osCpe: null, publishesHostPort: false, deviceRole: 'UNKNOWN', originHostIp: 'local', originHostName: null, networkName: null },
  { id: 2, ipAddress: '10.0.0.2', hostname: 'web-staging', macAddress: null, firstSeen: null, lastSeen: null, criticality: 'MEDIUM', discoveryScope: 'HOME', lastSeenIface: null, discoverySource: null, serviceCount: 0, osName: null, osAccuracy: null, osCpe: null, publishesHostPort: false, deviceRole: 'UNKNOWN', originHostIp: 'local', originHostName: null, networkName: null },
  { id: 3, ipAddress: '172.16.0.5', hostname: 'db-primary', macAddress: null, firstSeen: null, lastSeen: null, criticality: 'CRITICAL', discoveryScope: 'HOME', lastSeenIface: null, discoverySource: null, serviceCount: 0, osName: null, osAccuracy: null, osCpe: null, publishesHostPort: false, deviceRole: 'UNKNOWN', originHostIp: 'local', originHostName: null, networkName: null },
  { id: 4, ipAddress: '172.16.0.6', hostname: null, macAddress: null, firstSeen: null, lastSeen: null, criticality: 'LOW', discoveryScope: 'HOME', lastSeenIface: null, discoverySource: null, serviceCount: 0, osName: null, osAccuracy: null, osCpe: null, publishesHostPort: false, deviceRole: 'UNKNOWN', originHostIp: 'local', originHostName: null, networkName: null },
];

describe('<DevicePicker />', () => {
  it('opens the dropdown on focus and lists every device', async () => {
    const onChange = vi.fn();
    render(
      <DevicePicker devices={DEVICES} value={null} onChange={onChange} testId="picker" />
    );
    fireEvent.focus(screen.getByTestId('picker-input'));
    await waitFor(() => expect(screen.getByTestId('picker-list')).toBeInTheDocument());
    expect(screen.getByTestId('picker-option-1')).toBeInTheDocument();
    expect(screen.getByTestId('picker-option-2')).toBeInTheDocument();
    expect(screen.getByTestId('picker-option-3')).toBeInTheDocument();
    expect(screen.getByTestId('picker-option-4')).toBeInTheDocument();
  });

  it('filters by hostname substring (case-insensitive)', async () => {
    const onChange = vi.fn();
    render(
      <DevicePicker devices={DEVICES} value={null} onChange={onChange} testId="picker" />
    );
    fireEvent.focus(screen.getByTestId('picker-input'));
    fireEvent.change(screen.getByTestId('picker-input'), { target: { value: 'WEB' } });
    await waitFor(() => {
      expect(screen.getByTestId('picker-option-1')).toBeInTheDocument();
      expect(screen.getByTestId('picker-option-2')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('picker-option-3')).not.toBeInTheDocument();
    expect(screen.queryByTestId('picker-option-4')).not.toBeInTheDocument();
  });

  it('filters by IP substring', async () => {
    const onChange = vi.fn();
    render(
      <DevicePicker devices={DEVICES} value={null} onChange={onChange} testId="picker" />
    );
    fireEvent.focus(screen.getByTestId('picker-input'));
    fireEvent.change(screen.getByTestId('picker-input'), { target: { value: '172.16' } });
    await waitFor(() => {
      expect(screen.getByTestId('picker-option-3')).toBeInTheDocument();
      expect(screen.getByTestId('picker-option-4')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('picker-option-1')).not.toBeInTheDocument();
  });

  it('commits selection via onChange when an option is clicked', async () => {
    const onChange = vi.fn();
    render(
      <DevicePicker devices={DEVICES} value={null} onChange={onChange} testId="picker" />
    );
    fireEvent.focus(screen.getByTestId('picker-input'));
    fireEvent.mouseDown(screen.getByTestId('picker-option-3'));
    expect(onChange).toHaveBeenCalledWith(3);
  });

  it('renders the selected device label at rest and exposes a clear button', () => {
    const onChange = vi.fn();
    render(
      <DevicePicker devices={DEVICES} value={3} onChange={onChange} testId="picker" />
    );
    expect((screen.getByTestId('picker-input') as HTMLInputElement).value).toBe('db-primary (172.16.0.5)');
    fireEvent.click(screen.getByTestId('picker-clear'));
    expect(onChange).toHaveBeenCalledWith(null);
  });

  it('shows "No matches" when no device matches the query', async () => {
    const onChange = vi.fn();
    render(
      <DevicePicker devices={DEVICES} value={null} onChange={onChange} testId="picker" />
    );
    fireEvent.focus(screen.getByTestId('picker-input'));
    fireEvent.change(screen.getByTestId('picker-input'), { target: { value: 'nonexistent' } });
    await waitFor(() => {
      expect(screen.getByTestId('picker-empty')).toBeInTheDocument();
    });
  });
});

/** Builds a device whose hostname (`node-NN`) matches the query "node". */
function makeDevice(id: number): Device {
  return {
    id,
    ipAddress: `10.0.0.${id}`,
    hostname: `node-${String(id).padStart(2, '0')}`,
    macAddress: null,
    firstSeen: null,
    lastSeen: null,
    criticality: 'LOW',
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
}

describe('<DevicePicker /> 50-option render cap overflow', () => {
  it('shows an overflow footer with the hidden-match count when a query matches more than 50 devices', async () => {
    const fleet = Array.from({ length: 60 }, (_, i) => makeDevice(i + 1));
    render(
      <DevicePicker devices={fleet} value={null} onChange={vi.fn()} testId="picker" />
    );
    fireEvent.focus(screen.getByTestId('picker-input'));
    fireEvent.change(screen.getByTestId('picker-input'), { target: { value: 'node' } });
    await waitFor(() => expect(screen.getByTestId('picker-list')).toBeInTheDocument());

    // Render cap pinned: only 50 of the 60 matches become DOM rows.
    expect(screen.getAllByTestId(/^picker-option-/)).toHaveLength(50);

    // Overflow affordance: tells the operator how much is hidden (counts, not exact copy).
    const footer = screen.getByTestId('picker-overflow');
    expect(footer.textContent).toMatch(/\b50\b/);
    expect(footer.textContent).toMatch(/\b60\b/);
  });

  it('shows the overflow footer on focus with an empty query when the fleet exceeds the cap', async () => {
    const fleet = Array.from({ length: 60 }, (_, i) => makeDevice(i + 1));
    render(
      <DevicePicker devices={fleet} value={null} onChange={vi.fn()} testId="picker" />
    );
    fireEvent.focus(screen.getByTestId('picker-input'));
    await waitFor(() => expect(screen.getByTestId('picker-list')).toBeInTheDocument());

    expect(screen.getAllByTestId(/^picker-option-/)).toHaveLength(50);
    const footer = screen.getByTestId('picker-overflow');
    expect(footer.textContent).toMatch(/\b50\b/);
    expect(footer.textContent).toMatch(/\b60\b/);
  });

  it('renders NO overflow footer when matches exactly fill the cap (boundary: 50 of 50)', async () => {
    const fleet = Array.from({ length: 50 }, (_, i) => makeDevice(i + 1));
    render(
      <DevicePicker devices={fleet} value={null} onChange={vi.fn()} testId="picker" />
    );
    fireEvent.focus(screen.getByTestId('picker-input'));
    await waitFor(() => expect(screen.getByTestId('picker-list')).toBeInTheDocument());

    expect(screen.getAllByTestId(/^picker-option-/)).toHaveLength(50);
    expect(screen.queryByTestId('picker-overflow')).not.toBeInTheDocument();
  });

  it('renders NO overflow footer when matches fit comfortably under the cap', async () => {
    render(
      <DevicePicker devices={DEVICES} value={null} onChange={vi.fn()} testId="picker" />
    );
    fireEvent.focus(screen.getByTestId('picker-input'));
    await waitFor(() => expect(screen.getByTestId('picker-list')).toBeInTheDocument());

    expect(screen.queryByTestId('picker-overflow')).not.toBeInTheDocument();
  });
});
