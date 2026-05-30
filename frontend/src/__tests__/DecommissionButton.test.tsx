import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { DecommissionButton } from '../components/DecommissionButton';
import type { Device } from '../api/types';

const device: Device = {
  id: 42,
  ipAddress: '10.0.0.42',
  hostname: 'doomed-host',
  macAddress: null,
  firstSeen: null,
  lastSeen: null,
  criticality: 'HIGH',
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

describe('<DecommissionButton />', () => {
  it('renders nothing for VIEWER (isAdmin=false)', () => {
    const { container } = render(
      <DecommissionButton device={device} isAdmin={false} onConfirmed={vi.fn()} />
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('ADMIN click opens the confirm dialog', () => {
    render(<DecommissionButton device={device} isAdmin={true} onConfirmed={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: /decommission/i }));
    expect(screen.getByRole('dialog', { name: /confirm decommission/i })).toBeInTheDocument();
  });

  it('Confirm button is disabled until the hostname is typed verbatim', () => {
    render(<DecommissionButton device={device} isAdmin={true} onConfirmed={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: /decommission/i }));
    const confirmBtn = screen.getByRole('button', { name: /^confirm$/i }) as HTMLButtonElement;
    expect(confirmBtn.disabled).toBe(true);

    const input = screen.getByLabelText(/type hostname to confirm/i);
    fireEvent.change(input, { target: { value: 'doomed' } });
    expect(confirmBtn.disabled).toBe(true);

    fireEvent.change(input, { target: { value: 'doomed-host' } });
    expect(confirmBtn.disabled).toBe(false);
  });

  it('Confirm calls onConfirmed once', async () => {
    const onConfirmed = vi.fn().mockResolvedValue(undefined);
    render(<DecommissionButton device={device} isAdmin={true} onConfirmed={onConfirmed} />);
    fireEvent.click(screen.getByRole('button', { name: /decommission/i }));
    fireEvent.change(screen.getByLabelText(/type hostname to confirm/i), { target: { value: 'doomed-host' } });
    fireEvent.click(screen.getByRole('button', { name: /^confirm$/i }));
    await waitFor(() => expect(onConfirmed).toHaveBeenCalledTimes(1));
  });

  it('Cancel closes the dialog without calling onConfirmed', () => {
    const onConfirmed = vi.fn();
    render(<DecommissionButton device={device} isAdmin={true} onConfirmed={onConfirmed} />);
    fireEvent.click(screen.getByRole('button', { name: /decommission/i }));
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    expect(onConfirmed).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('falls back to the IP when hostname is null', () => {
    const ipOnly: Device = { ...device, hostname: null };
    render(<DecommissionButton device={ipOnly} isAdmin={true} onConfirmed={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: /decommission/i }));
    const confirmBtn = screen.getByRole('button', { name: /^confirm$/i }) as HTMLButtonElement;
    const input = screen.getByLabelText(/type hostname to confirm/i);
    fireEvent.change(input, { target: { value: '10.0.0.42' } });
    expect(confirmBtn.disabled).toBe(false);
  });
});
