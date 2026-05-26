import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DiscoveryControlPanel } from '../components/DiscoveryControlPanel';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    listInterfaces: vi.fn(),
    discoverPassive: vi.fn(),
  },
}));

const listInterfaces = vi.mocked(api.listInterfaces);
const discoverPassive = vi.mocked(api.discoverPassive);

beforeEach(() => {
  listInterfaces.mockReset();
  discoverPassive.mockReset();
});

describe('<DiscoveryControlPanel />', () => {
  it('VIEWER sees the form rendered read-only — controls disabled, submit disabled', async () => {
    listInterfaces.mockResolvedValueOnce([]);
    render(<DiscoveryControlPanel isAdmin={false} />);
    expect(screen.getByText(/Read-only — ADMIN required/i)).toBeInTheDocument();
    const ifaceSelect = screen.getByTestId('iface-select') as HTMLSelectElement;
    expect(ifaceSelect).toBeDisabled();
    const runBtn = screen.getByRole('button', { name: /Run passive discovery/i }) as HTMLButtonElement;
    expect(runBtn).toBeDisabled();
  });

  it('ADMIN sees the form interactive and uses fetched interfaces', async () => {
    listInterfaces.mockResolvedValueOnce([
      { name: 'enp3s0', displayName: 'enp3s0', mtu: 1500 },
    ]);
    render(<DiscoveryControlPanel isAdmin={true} />);
    await waitFor(() => {
      const select = screen.getByTestId('iface-select') as HTMLSelectElement;
      expect(Array.from(select.options).map(o => o.value)).toContain('enp3s0');
    });
    expect(screen.getByTestId('iface-select')).not.toBeDisabled();
  });

  it('ADMIN can submit a sweep and the results table renders', async () => {
    listInterfaces.mockResolvedValueOnce([]); // fall back to eth0/wlan0
    discoverPassive.mockResolvedValueOnce({
      discovered: 3,
      deviceIds: [1, 2, 3],
      perSourceCount: { ARP: 2, MDNS: 1 } as Record<'ARP' | 'MDNS' | 'PCAP' | 'LLDP' | 'CDP', number>,
      sweepId: 9,
    });

    render(<DiscoveryControlPanel isAdmin={true} />);
    await waitFor(() => expect(screen.getByTestId('iface-select')).toBeInTheDocument());

    fireEvent.change(screen.getByTestId('window-seconds-input'), { target: { value: '45' } });
    fireEvent.click(screen.getByRole('button', { name: /Run passive discovery/i }));

    await waitFor(() => {
      expect(discoverPassive).toHaveBeenCalledTimes(1);
    });
    expect(discoverPassive).toHaveBeenCalledWith({
      iface: 'eth0',
      durationSeconds: 45,
      sources: ['ARP', 'MDNS'],
    });
    await waitFor(() => {
      expect(screen.getByTestId('discovery-results')).toBeInTheDocument();
      expect(screen.getByText(/sweep #9/)).toBeInTheDocument();
    });
  });

  it('renders an error banner on submit failure', async () => {
    listInterfaces.mockResolvedValueOnce([]);
    discoverPassive.mockRejectedValueOnce(new Error('500 boom'));
    render(<DiscoveryControlPanel isAdmin={true} />);
    await waitFor(() => expect(screen.getByTestId('iface-select')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /Run passive discovery/i }));
    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/500 boom/);
    });
  });

  it('toggling sources updates the request payload', async () => {
    listInterfaces.mockResolvedValueOnce([]);
    discoverPassive.mockResolvedValueOnce({
      discovered: 0,
      deviceIds: [],
      perSourceCount: {} as Record<'ARP' | 'MDNS' | 'PCAP' | 'LLDP' | 'CDP', number>,
      sweepId: null,
    });

    render(<DiscoveryControlPanel isAdmin={true} />);
    await waitFor(() => expect(screen.getByTestId('iface-select')).toBeInTheDocument());

    fireEvent.click(screen.getByTestId('source-mdns')); // toggle off
    fireEvent.click(screen.getByTestId('source-pcap')); // toggle on
    fireEvent.click(screen.getByRole('button', { name: /Run passive discovery/i }));

    await waitFor(() => {
      expect(discoverPassive).toHaveBeenCalledWith(
        expect.objectContaining({ sources: ['ARP', 'PCAP'] })
      );
    });
  });
});
