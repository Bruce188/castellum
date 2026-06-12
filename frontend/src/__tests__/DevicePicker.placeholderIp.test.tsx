import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { DevicePicker } from '../components/DevicePicker';
import type { Device } from '../api/types';

const PLACEHOLDER = 'mac:aa-bb-cc-dd-ee-ff';

function makeDevice(id: number, ipAddress: string, hostname: string | null): Device {
  return {
    id, ipAddress, hostname, macAddress: null, firstSeen: null, lastSeen: null,
    criticality: 'LOW', discoveryScope: 'HOME', lastSeenIface: null,
    discoverySource: null, serviceCount: 0, osName: null, osAccuracy: null,
    osCpe: null, publishesHostPort: false, deviceRole: 'UNKNOWN',
    originHostIp: 'local', originHostName: null, networkName: null,
  };
}

const DEVICES: Device[] = [
  makeDevice(1, '10.0.0.1', 'web-prod'),
  makeDevice(7, PLACEHOLDER, null),
  makeDevice(3, '172.16.0.5', 'db-primary'),
];

describe('<DevicePicker /> MAC-placeholder IP rendering', () => {
  it('renders "no IP" in the option text instead of the raw mac: placeholder', async () => {
    render(
      <DevicePicker devices={DEVICES} value={null} onChange={vi.fn()} testId="picker" />
    );
    fireEvent.focus(screen.getByTestId('picker-input'));
    await waitFor(() => expect(screen.getByTestId('picker-list')).toBeInTheDocument());

    const placeholderOption = screen.getByTestId('picker-option-7');
    expect(placeholderOption.textContent).toContain('no IP');
    expect(placeholderOption.textContent).not.toContain(PLACEHOLDER);
    // Raw placeholder string appears nowhere in the rendered list.
    expect(screen.queryByText(PLACEHOLDER)).not.toBeInTheDocument();

    // Normal devices keep their real IPs.
    expect(screen.getByTestId('picker-option-1').textContent).toContain('10.0.0.1');
    expect(screen.getByTestId('picker-option-3').textContent).toContain('172.16.0.5');
  });

  it('text filter matches the displayed "no IP" label, so typing "no" finds the placeholder device', async () => {
    render(
      <DevicePicker devices={DEVICES} value={null} onChange={vi.fn()} testId="picker" />
    );
    const input = screen.getByTestId('picker-input');
    fireEvent.focus(input);
    fireEvent.change(input, { target: { value: 'no' } });

    await waitFor(() => expect(screen.getByTestId('picker-list')).toBeInTheDocument());
    expect(screen.getByTestId('picker-option-7')).toBeInTheDocument();
    // Devices whose hostname/display IP lack "no" are filtered out.
    expect(screen.queryByTestId('picker-option-1')).not.toBeInTheDocument();
    expect(screen.queryByTestId('picker-option-3')).not.toBeInTheDocument();
  });

  it('text filter does NOT match the raw "mac:" key the option never shows', async () => {
    render(
      <DevicePicker devices={DEVICES} value={null} onChange={vi.fn()} testId="picker" />
    );
    const input = screen.getByTestId('picker-input');
    fireEvent.focus(input);
    fireEvent.change(input, { target: { value: 'mac:' } });

    await waitFor(() => expect(screen.getByTestId('picker-empty')).toBeInTheDocument());
    expect(screen.queryByTestId('picker-option-7')).not.toBeInTheDocument();
    expect(screen.queryByTestId('picker-list')).not.toBeInTheDocument();
  });
});
