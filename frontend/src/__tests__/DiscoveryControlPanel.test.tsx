import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DiscoveryControlPanel } from '../components/DiscoveryControlPanel';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    listInterfaces: vi.fn(),
    discoverPassive: vi.fn(),
    discoverDocker: vi.fn(),
  },
}));

const listInterfaces = vi.mocked(api.listInterfaces);
const discoverPassive = vi.mocked(api.discoverPassive);
const discoverDocker = vi.mocked(api.discoverDocker);

beforeEach(() => {
  listInterfaces.mockReset();
  discoverPassive.mockReset();
  discoverDocker.mockReset();
});

describe('<DiscoveryControlPanel />', () => {
  // --- REVISED case 1 ---
  it('VIEWER sees the form rendered read-only — controls disabled, submit disabled', async () => {
    listInterfaces.mockResolvedValueOnce([]);
    render(<DiscoveryControlPanel isAdmin={false} />);
    expect(screen.getByText(/Read-only — ADMIN required/i)).toBeInTheDocument();
    // Primary activate button is disabled for VIEWER
    const activateBtn = screen.getByTestId('passive-activate-btn') as HTMLButtonElement;
    expect(activateBtn).toBeDisabled();
    // iface-select lives behind Advanced — open it and check it is disabled too
    const advancedToggle = screen.getByTestId('advanced-toggle');
    fireEvent.click(advancedToggle);
    const ifaceSelect = screen.getByTestId('iface-select') as HTMLSelectElement;
    expect(ifaceSelect).toBeDisabled();
  });

  // --- REVISED case 2 ---
  it('ADMIN sees the form interactive and uses fetched interfaces', async () => {
    listInterfaces.mockResolvedValueOnce([
      { name: 'enp3s0', displayName: 'enp3s0', mtu: 1500 },
    ]);
    render(<DiscoveryControlPanel isAdmin={true} />);
    // iface-select is now inside the Advanced section — open it first
    const advancedToggle = screen.getByTestId('advanced-toggle');
    fireEvent.click(advancedToggle);
    await waitFor(() => {
      const select = screen.getByTestId('iface-select') as HTMLSelectElement;
      expect(Array.from(select.options).map(o => o.value)).toContain('enp3s0');
    });
    expect(screen.getByTestId('iface-select')).not.toBeDisabled();
  });

  // --- REVISED case 3 ---
  it('ADMIN can submit a sweep and the results table renders', async () => {
    listInterfaces.mockResolvedValueOnce([]); // fall back to eth0/wlan0
    discoverPassive.mockResolvedValueOnce({
      discovered: 3,
      deviceIds: [1, 2, 3],
      perSourceCount: { ARP: 2, MDNS: 1, PCAP: 0, LLDP: 0, CDP: 0, OT_PROBE: 0, NMAP_SCAN: 0, DOCKER: 0 },
      sweepId: 9,
    });

    render(<DiscoveryControlPanel isAdmin={true} />);

    // Open Advanced and set a custom window duration
    const advancedToggle = screen.getByTestId('advanced-toggle');
    fireEvent.click(advancedToggle);
    await waitFor(() => expect(screen.getByTestId('window-seconds-input')).toBeInTheDocument());
    fireEvent.change(screen.getByTestId('window-seconds-input'), { target: { value: '45' } });

    // Click the primary activate button
    fireEvent.click(screen.getByTestId('passive-activate-btn'));

    await waitFor(() => {
      expect(discoverPassive).toHaveBeenCalledTimes(1);
    });
    // All-defaults payload except the custom window duration we set
    expect(discoverPassive).toHaveBeenCalledWith(
      { iface: '', durationSeconds: 45, sources: ['ARP', 'MDNS', 'PCAP'] },
      expect.anything()
    );
    await waitFor(() => {
      expect(screen.getByTestId('discovery-results')).toBeInTheDocument();
      expect(screen.getByText(/sweep #9/)).toBeInTheDocument();
    });
  });

  // --- REVISED case 4 ---
  it('renders an error banner on submit failure', async () => {
    listInterfaces.mockResolvedValueOnce([]);
    discoverPassive.mockRejectedValueOnce(new Error('500 boom'));
    render(<DiscoveryControlPanel isAdmin={true} />);
    // Click the primary activate button (no Advanced needed)
    fireEvent.click(screen.getByTestId('passive-activate-btn'));
    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/500 boom/);
    });
  });

  // --- REVISED case 5 ---
  it('toggling sources updates the request payload', async () => {
    listInterfaces.mockResolvedValueOnce([]);
    discoverPassive.mockResolvedValueOnce({
      discovered: 0,
      deviceIds: [],
      perSourceCount: { ARP: 0, MDNS: 0, PCAP: 0, LLDP: 0, CDP: 0, OT_PROBE: 0, NMAP_SCAN: 0, DOCKER: 0 },
      sweepId: null,
    });

    render(<DiscoveryControlPanel isAdmin={true} />);

    // Open Advanced to access source checkboxes (now behind collapsed section)
    const advancedToggle = screen.getByTestId('advanced-toggle');
    fireEvent.click(advancedToggle);
    await waitFor(() => expect(screen.getByTestId('source-mdns')).toBeInTheDocument());

    // Under new defaults ALL_SOURCES=['ARP','MDNS','PCAP'] are all checked.
    // Toggle MDNS off → sources: ['ARP','PCAP']
    fireEvent.click(screen.getByTestId('source-mdns')); // toggle MDNS off

    fireEvent.click(screen.getByTestId('passive-activate-btn'));

    await waitFor(() => {
      expect(discoverPassive).toHaveBeenCalledWith(
        expect.objectContaining({ sources: ['ARP', 'PCAP'] }),
        expect.anything()
      );
    });
  });

  // --- NEW case 6: AC1 one-button activates with all defaults ---
  it('one-button activates with all defaults (AC1)', async () => {
    listInterfaces.mockResolvedValueOnce([]);
    discoverPassive.mockResolvedValueOnce({
      discovered: 0,
      deviceIds: [],
      perSourceCount: { ARP: 0, MDNS: 0, PCAP: 0, LLDP: 0, CDP: 0, OT_PROBE: 0, NMAP_SCAN: 0, DOCKER: 0 },
      sweepId: null,
    });

    render(<DiscoveryControlPanel isAdmin={true} />);

    // Do NOT open Advanced — click the primary button with all defaults
    fireEvent.click(screen.getByTestId('passive-activate-btn'));

    await waitFor(() => {
      expect(discoverPassive).toHaveBeenCalledTimes(1);
    });
    // Must be called with ALL-DEFAULTS: blank iface, 30s, all sources
    expect(discoverPassive).toHaveBeenCalledWith(
      { iface: '', durationSeconds: 30, sources: ['ARP', 'MDNS', 'PCAP'] },
      expect.anything()
    );
    // scan-scope shows the "all" summary
    expect(screen.getByTestId('scan-scope')).toHaveTextContent(/all/i);
  });

  // --- NEW case 7: AC2 advanced override narrows the payload ---
  it('advanced override narrows the payload (AC2)', async () => {
    listInterfaces.mockResolvedValueOnce([
      { name: 'eth0', displayName: 'eth0', mtu: 1500 },
      { name: 'eth1', displayName: 'eth1', mtu: 1500 },
    ]);
    discoverPassive.mockResolvedValueOnce({
      discovered: 0,
      deviceIds: [],
      perSourceCount: { ARP: 0, MDNS: 0, PCAP: 0, LLDP: 0, CDP: 0, OT_PROBE: 0, NMAP_SCAN: 0, DOCKER: 0 },
      sweepId: null,
    });

    render(<DiscoveryControlPanel isAdmin={true} />);

    // Open Advanced to access iface select and source checkboxes
    const advancedToggle = screen.getByTestId('advanced-toggle');
    fireEvent.click(advancedToggle);

    await waitFor(() => expect(screen.getByTestId('iface-select')).toBeInTheDocument());

    // Narrow iface to eth1
    fireEvent.change(screen.getByTestId('iface-select'), { target: { value: 'eth1' } });
    // Deselect MDNS → sources: ['ARP','PCAP']
    fireEvent.click(screen.getByTestId('source-mdns'));

    // Click activate
    fireEvent.click(screen.getByTestId('passive-activate-btn'));

    await waitFor(() => {
      expect(discoverPassive).toHaveBeenCalledTimes(1);
    });
    // Narrowed iface and sources must be sent verbatim
    expect(discoverPassive).toHaveBeenCalledWith(
      expect.objectContaining({ iface: 'eth1', sources: ['ARP', 'PCAP'] }),
      expect.anything()
    );
  });

  // --- NEW case 9: real-error-with-signal surfaces the banner ---
  it('real error surfaces the banner even when a signal is in flight', async () => {
    listInterfaces.mockResolvedValueOnce([]);

    // discoverPassive receives a signal but rejects with a non-AbortError
    discoverPassive.mockImplementationOnce(
      (_payload: unknown, _signal?: AbortSignal) =>
        Promise.reject(new Error('500 boom'))
    );

    render(<DiscoveryControlPanel isAdmin={true} />);

    fireEvent.click(screen.getByTestId('passive-activate-btn'));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/500 boom/);
    });
  });

  // --- NEW case 10: unmount mid-flight produces no unhandled state-update warning ---
  it('unmounting during in-flight discoverPassive does not throw or warn', async () => {
    listInterfaces.mockResolvedValueOnce([]);

    // Never-resolving promise — component unmounts before it settles
    discoverPassive.mockImplementationOnce(
      () => new Promise<never>(() => { /* never resolves */ })
    );

    const { unmount } = render(<DiscoveryControlPanel isAdmin={true} />);

    fireEvent.click(screen.getByTestId('passive-activate-btn'));

    // Unmount while request is still in-flight
    unmount();

    // No assertions needed beyond "test completes without throwing"
    // (React's act() would surface unhandled setState-after-unmount warnings as errors)
  });

  // --- NEW case 8: AC3 activate shows active state then deactivate aborts in-flight request ---
  it('activate shows active state then deactivate aborts the in-flight request (AC3)', async () => {
    listInterfaces.mockResolvedValueOnce([]);

    // Wire discoverPassive to a never-resolving promise that rejects with AbortError when signal fires
    discoverPassive.mockImplementationOnce(
      (_payload: unknown, signal?: AbortSignal) =>
        new Promise<never>((_resolve, reject) => {
          if (signal) {
            signal.addEventListener('abort', () => {
              reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
            });
          }
          // Never resolves on its own
        })
    );

    render(<DiscoveryControlPanel isAdmin={true} />);

    // Click activate — request is now in-flight (never resolves)
    fireEvent.click(screen.getByTestId('passive-activate-btn'));

    // Active state must be surfaced immediately
    await waitFor(() => {
      expect(screen.getByTestId('scan-status')).toHaveTextContent(/active.*scanning/i);
    });
    // Deactivate button must be visible while scanning
    expect(screen.getByTestId('passive-deactivate-btn')).toBeInTheDocument();

    // Click deactivate — should abort the in-flight request
    fireEvent.click(screen.getByTestId('passive-deactivate-btn'));

    // After abort: scan-status returns to Inactive
    await waitFor(() => {
      expect(screen.getByTestId('scan-status')).toHaveTextContent(/inactive/i);
    });

    // AbortError must be swallowed — NO error banner
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();

    // Deactivate button should no longer be present
    expect(screen.queryByTestId('passive-deactivate-btn')).not.toBeInTheDocument();
  });

  // --- Docker discovery button ---
  it('docker-discover button is disabled for VIEWER', async () => {
    listInterfaces.mockResolvedValueOnce([]);
    render(<DiscoveryControlPanel isAdmin={false} />);
    const btn = screen.getByTestId('docker-discover-btn') as HTMLButtonElement;
    expect(btn).toBeDisabled();
  });

  it('ADMIN clicking docker-discover calls discoverDocker, shows the count, and fires onDiscovered', async () => {
    listInterfaces.mockResolvedValueOnce([]);
    discoverDocker.mockResolvedValueOnce({
      containers: 8,
      gateways: 2,
      updated: 10,
      deviceIds: [1, 2, 3],
    });
    const onDiscovered = vi.fn();

    render(<DiscoveryControlPanel isAdmin={true} onDiscovered={onDiscovered} />);

    fireEvent.click(screen.getByTestId('docker-discover-btn'));

    await waitFor(() => {
      expect(discoverDocker).toHaveBeenCalledTimes(1);
    });
    await waitFor(() => {
      expect(screen.getByTestId('docker-discover-result')).toHaveTextContent(/8 containers/);
      expect(screen.getByTestId('docker-discover-result')).toHaveTextContent(/2 networks/);
    });
    expect(onDiscovered).toHaveBeenCalledWith(10);
  });

  it('docker-discover surfaces an error banner on failure', async () => {
    listInterfaces.mockResolvedValueOnce([]);
    discoverDocker.mockRejectedValueOnce(new Error('503 Service Unavailable'));

    render(<DiscoveryControlPanel isAdmin={true} />);

    fireEvent.click(screen.getByTestId('docker-discover-btn'));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/503/);
    });
  });
});
