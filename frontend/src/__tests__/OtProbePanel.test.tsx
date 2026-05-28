import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { OtProbePanel } from '../components/OtProbePanel';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    probeOt: vi.fn(),
    listDevices: vi.fn(),
    probeOtOnce: vi.fn(),
  },
}));

const probeOt = vi.mocked(api.probeOt);
const listDevices = vi.mocked(api.listDevices);
const probeOtOnce = vi.mocked(api.probeOtOnce);

const MOCK_PROBE_RESULT = {
  host: '127.0.0.1',
  port: 502,
  protocol: 'MODBUS_TCP' as const,
  vendor: 'Castellum',
  product: 'MOCK-1',
  version: '1.0',
  rawFields: { '0': 'Castellum', '1': 'MOCK-1' },
  deviceId: 5,
  serviceId: 6,
  observedAt: '2026-05-26T12:00:00Z',
};

function makePage(ips: string[]) {
  return {
    content: ips.map((ip, i) => ({
      id: i + 1,
      ipAddress: ip,
      hostname: null,
      macAddress: null,
      firstSeen: null,
      lastSeen: null,
      criticality: 'LOW' as const,
      discoveryScope: 'HOME' as const,
      lastSeenIface: null,
      discoverySource: null,
    })),
    totalElements: ips.length,
    totalPages: 1,
    number: 0,
    size: 200,
  };
}

beforeEach(() => {
  probeOt.mockReset();
  listDevices.mockReset();
  probeOtOnce.mockReset();
  // Default: listDevices resolves empty, probeOtOnce never called
  listDevices.mockResolvedValue(makePage([]));
});

// ---------------------------------------------------------------------------
// Helper: open the advanced toggle so the single-protocol form is accessible
// ---------------------------------------------------------------------------
function openAdvancedToggle() {
  // The single-protocol form lives under <details data-testid="ot-advanced-toggle">
  fireEvent.click(screen.getByTestId('ot-advanced-toggle'));
}

describe('<OtProbePanel />', () => {
  // -------------------------------------------------------------------------
  // Existing tests — revised to open the advanced toggle before querying
  // single-protocol controls (AC4: form relocated under ot-advanced-toggle)
  // -------------------------------------------------------------------------

  it('VIEWER sees the panel read-only (controls disabled, badge shown)', () => {
    render(<OtProbePanel isAdmin={false} />);
    expect(screen.getByText(/Read-only — ADMIN required/i)).toBeInTheDocument();
    openAdvancedToggle();
    expect(screen.getByTestId('ot-host-input')).toBeDisabled();
    expect(screen.getByTestId('ot-port-input')).toBeDisabled();
    expect(screen.getByTestId('ot-protocol-select')).toBeDisabled();
    expect(screen.getByRole('button', { name: /Run probe/i })).toBeDisabled();
  });

  it('ADMIN can submit a probe and the result renders', async () => {
    probeOt.mockResolvedValueOnce(MOCK_PROBE_RESULT);

    render(<OtProbePanel isAdmin={true} />);
    openAdvancedToggle();
    fireEvent.change(screen.getByTestId('ot-host-input'), { target: { value: '127.0.0.1' } });
    fireEvent.click(screen.getByRole('button', { name: /Run probe/i }));

    await waitFor(() => {
      expect(probeOt).toHaveBeenCalledWith({
        host: '127.0.0.1',
        port: 502,
        protocol: 'MODBUS_TCP',
      });
    });
    await waitFor(() => {
      expect(screen.getByTestId('ot-probe-result')).toHaveTextContent('Castellum');
      expect(screen.getByTestId('ot-probe-result')).toHaveTextContent('MOCK-1');
    });
  });

  it('changing the protocol updates the default port', () => {
    render(<OtProbePanel isAdmin={true} />);
    openAdvancedToggle();
    const portInput = screen.getByTestId('ot-port-input') as HTMLInputElement;
    expect(portInput.value).toBe('502');

    fireEvent.change(screen.getByTestId('ot-protocol-select'), { target: { value: 'S7COMM' } });
    expect(portInput.value).toBe('102');

    fireEvent.change(screen.getByTestId('ot-protocol-select'), { target: { value: 'BACNET_IP' } });
    expect(portInput.value).toBe('47808');
  });

  it('protocol dropdown lists only read-fingerprint protocols (no write protocols)', () => {
    render(<OtProbePanel isAdmin={true} />);
    openAdvancedToggle();
    const select = screen.getByTestId('ot-protocol-select') as HTMLSelectElement;
    const values = Array.from(select.options).map(o => o.value).sort();
    // Constraint: protocol values are read-fingerprint only — must match backend OtProtocol enum exactly.
    expect(values).toEqual(['BACNET_IP', 'DNP3', 'MODBUS_TCP', 'S7COMM']);
  });

  it('renders an error banner on probe failure', async () => {
    probeOt.mockRejectedValueOnce(new Error('502 unreachable'));
    render(<OtProbePanel isAdmin={true} />);
    openAdvancedToggle();
    fireEvent.click(screen.getByRole('button', { name: /Run probe/i }));
    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/502 unreachable/);
    });
  });

  it('names the four ICS protocols and default ports in the help line', () => {
    render(<OtProbePanel isAdmin={true} />);
    const help = screen.getByTestId('ot-protocol-help');
    expect(help).toHaveTextContent(/Modbus.*502/);
    expect(help).toHaveTextContent(/DNP3.*20000/);
    expect(help).toHaveTextContent(/S7comm.*102/);
    expect(help).toHaveTextContent(/BACnet.*47808/);
  });

  it('shows the operator how to verify a probe ran (verify-help note)', () => {
    render(<OtProbePanel isAdmin={true} />);
    expect(screen.getByTestId('ot-verify-help')).toHaveTextContent(/OT\/ICS protocols detected/i);
  });

  // -------------------------------------------------------------------------
  // New tests — AC1 / AC3 / AC4 / VIEWER gating on sweep button
  // -------------------------------------------------------------------------

  it('AC1 — sweep button exists and dispatches probeOtOnce for each host × protocol', async () => {
    const hosts = ['192.168.1.10', '192.168.1.20'];
    listDevices.mockResolvedValue(makePage(hosts));

    // probeOtOnce resolves immediately for every cell
    probeOtOnce.mockResolvedValue({
      ...MOCK_PROBE_RESULT,
      vendor: 'ACME',
      product: 'PLC-v1',
    });

    render(<OtProbePanel isAdmin={true} />);

    // The primary sweep button must exist without opening the toggle
    const sweepBtn = screen.getByTestId('ot-sweep-all-btn');
    expect(sweepBtn).toBeInTheDocument();

    fireEvent.click(sweepBtn);

    // All 8 combinations (2 hosts × 4 protocols) must be probed
    await waitFor(() => {
      expect(probeOtOnce).toHaveBeenCalledTimes(8);
    });

    // Verify all 4 protocols appear across the calls
    const calledProtocols = probeOtOnce.mock.calls.map(c => c[1]);
    expect(calledProtocols).toContain('MODBUS_TCP');
    expect(calledProtocols).toContain('DNP3');
    expect(calledProtocols).toContain('S7COMM');
    expect(calledProtocols).toContain('BACNET_IP');

    // Verify default ports used
    const callMap = probeOtOnce.mock.calls.map(c => ({ host: c[0], protocol: c[1], port: c[2] }));
    expect(callMap).toContainEqual(expect.objectContaining({ protocol: 'MODBUS_TCP', port: 502 }));
    expect(callMap).toContainEqual(expect.objectContaining({ protocol: 'DNP3', port: 20000 }));
    expect(callMap).toContainEqual(expect.objectContaining({ protocol: 'S7COMM', port: 102 }));
    expect(callMap).toContainEqual(expect.objectContaining({ protocol: 'BACNET_IP', port: 47808 }));

    // The retrying probeOt must NOT be used by the sweep path
    expect(probeOt).not.toHaveBeenCalled();
  });

  it('AC3 — ot-sweep-progress shows running tally and ot-sweep-grid shows per-cell status', async () => {
    const hosts = ['10.0.0.1'];
    listDevices.mockResolvedValue(makePage(hosts));

    // Resolve all 4 cells immediately
    probeOtOnce.mockResolvedValue({
      ...MOCK_PROBE_RESULT,
      host: '10.0.0.1',
      vendor: 'ACME',
      product: 'PLC-v2',
    });

    render(<OtProbePanel isAdmin={true} />);

    fireEvent.click(screen.getByTestId('ot-sweep-all-btn'));

    // Progress element must appear
    await waitFor(() => {
      expect(screen.getByTestId('ot-sweep-progress')).toBeInTheDocument();
    });

    // Grid element must appear
    await waitFor(() => {
      expect(screen.getByTestId('ot-sweep-grid')).toBeInTheDocument();
    });

    // After all cells settle, progress shows 4/4
    await waitFor(() => {
      expect(screen.getByTestId('ot-sweep-progress')).toHaveTextContent('4/4');
    });

    // Each per-cell testid must exist in the grid
    const protocols = ['MODBUS_TCP', 'DNP3', 'S7COMM', 'BACNET_IP'];
    for (const proto of protocols) {
      await waitFor(() => {
        expect(screen.getByTestId(`ot-sweep-cell-10.0.0.1-${proto}`)).toBeInTheDocument();
      });
    }
  });

  it('AC3 — partial results appear before all cells complete', async () => {
    const hosts = ['10.0.0.1'];
    listDevices.mockResolvedValue(makePage(hosts));

    // Use individual resolvers so we control settlement order
    let resolveFirst!: (v: typeof MOCK_PROBE_RESULT) => void;
    let resolveRest!: (v: typeof MOCK_PROBE_RESULT) => void;

    const firstSettled = new Promise<typeof MOCK_PROBE_RESULT>((res) => { resolveFirst = res; });
    const restSettled = new Promise<typeof MOCK_PROBE_RESULT>((res) => { resolveRest = res; });

    // First call uses a deferred promise; subsequent calls use another deferred
    probeOtOnce
      .mockReturnValueOnce(firstSettled)
      .mockReturnValue(restSettled);

    render(<OtProbePanel isAdmin={true} />);
    fireEvent.click(screen.getByTestId('ot-sweep-all-btn'));

    // Settle the first probe
    resolveFirst({ ...MOCK_PROBE_RESULT, host: '10.0.0.1', vendor: 'PartialVendor' });

    // Progress should appear and show at least 1 completed before all 4 are done
    await waitFor(() => {
      const progress = screen.getByTestId('ot-sweep-progress');
      // tally text contains something like "1/4" (partial)
      expect(progress.textContent).toMatch(/\d+\/4/);
    });

    // Now resolve the rest
    resolveRest({ ...MOCK_PROBE_RESULT, host: '10.0.0.1' });

    await waitFor(() => {
      expect(screen.getByTestId('ot-sweep-progress')).toHaveTextContent('4/4');
    });
  });

  it('AC4 — advanced toggle exposes the single-protocol form which still dispatches api.probeOt', async () => {
    probeOt.mockResolvedValueOnce(MOCK_PROBE_RESULT);

    render(<OtProbePanel isAdmin={true} />);

    // The advanced toggle must exist
    const toggle = screen.getByTestId('ot-advanced-toggle');
    expect(toggle).toBeInTheDocument();

    // Before opening: single-protocol controls may not be visible
    // Open the toggle
    fireEvent.click(toggle);

    // Existing single-protocol controls must be present
    expect(screen.getByTestId('ot-host-input')).toBeInTheDocument();
    expect(screen.getByTestId('ot-port-input')).toBeInTheDocument();
    expect(screen.getByTestId('ot-protocol-select')).toBeInTheDocument();

    // Submit the single-protocol form
    fireEvent.change(screen.getByTestId('ot-host-input'), { target: { value: '10.0.0.5' } });
    fireEvent.click(screen.getByRole('button', { name: /Run probe/i }));

    await waitFor(() => {
      expect(probeOt).toHaveBeenCalledWith({
        host: '10.0.0.5',
        port: 502,
        protocol: 'MODBUS_TCP',
      });
    });

    // Result renders under the advanced section
    await waitFor(() => {
      expect(screen.getByTestId('ot-probe-result')).toHaveTextContent('Castellum');
    });

    // The sweep path (probeOtOnce) must NOT have been called by the single-protocol form
    expect(probeOtOnce).not.toHaveBeenCalled();
  });

  it('VIEWER — sweep button is disabled', () => {
    render(<OtProbePanel isAdmin={false} />);
    expect(screen.getByTestId('ot-sweep-all-btn')).toBeDisabled();
  });
});
