import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { OtProbePanel } from '../components/OtProbePanel';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    probeOt: vi.fn(),
  },
}));

const probeOt = vi.mocked(api.probeOt);

beforeEach(() => {
  probeOt.mockReset();
});

describe('<OtProbePanel />', () => {
  it('VIEWER sees the panel read-only (controls disabled, badge shown)', () => {
    render(<OtProbePanel isAdmin={false} />);
    expect(screen.getByText(/Read-only — ADMIN required/i)).toBeInTheDocument();
    expect(screen.getByTestId('ot-host-input')).toBeDisabled();
    expect(screen.getByTestId('ot-port-input')).toBeDisabled();
    expect(screen.getByTestId('ot-protocol-select')).toBeDisabled();
    expect(screen.getByRole('button', { name: /Run probe/i })).toBeDisabled();
  });

  it('ADMIN can submit a probe and the result renders', async () => {
    probeOt.mockResolvedValueOnce({
      host: '127.0.0.1',
      port: 502,
      protocol: 'MODBUS_TCP',
      vendor: 'Castellum',
      product: 'MOCK-1',
      version: '1.0',
      rawFields: { '0': 'Castellum', '1': 'MOCK-1' },
      deviceId: 5,
      serviceId: 6,
      observedAt: '2026-05-26T12:00:00Z',
    });

    render(<OtProbePanel isAdmin={true} />);
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
    const portInput = screen.getByTestId('ot-port-input') as HTMLInputElement;
    expect(portInput.value).toBe('502');

    fireEvent.change(screen.getByTestId('ot-protocol-select'), { target: { value: 'S7COMM' } });
    expect(portInput.value).toBe('102');

    fireEvent.change(screen.getByTestId('ot-protocol-select'), { target: { value: 'BACNET_IP' } });
    expect(portInput.value).toBe('47808');
  });

  it('protocol dropdown lists only read-fingerprint protocols (no write protocols)', () => {
    render(<OtProbePanel isAdmin={true} />);
    const select = screen.getByTestId('ot-protocol-select') as HTMLSelectElement;
    const values = Array.from(select.options).map(o => o.value).sort();
    // Constraint: protocol values are read-fingerprint only — must match backend OtProtocol enum exactly.
    expect(values).toEqual(['BACNET_IP', 'DNP3', 'MODBUS_TCP', 'S7COMM']);
  });

  it('renders an error banner on probe failure', async () => {
    probeOt.mockRejectedValueOnce(new Error('502 unreachable'));
    render(<OtProbePanel isAdmin={true} />);
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
});
