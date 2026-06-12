/**
 * ScanTriggerForm "Skip host discovery" checkbox.
 *
 * Locked design pinned here:
 *   - The checkbox labeled exactly "Skip host discovery" renders ONLY when the
 *     selected scan type is SERVICE_DETECT — the backend ignores the flag for
 *     PING_SWEEP / OS_FINGERPRINT, so offering it there would be a silent no-op.
 *   - UNCHECKED (default): the POST /api/scan body must NOT contain the key
 *     `skipHostDiscovery` at all (protects existing payload shapes).
 *   - CHECKED + SERVICE_DETECT: body contains `skipHostDiscovery: true`
 *     alongside cidr/type.
 *   - Switching the type away from SERVICE_DETECT drops the key from the
 *     submitted body even if the checkbox was checked beforehand.
 *
 * Mocking style mirrors ScanTriggerForm.cidr.test.tsx (mock api client +
 * useScanStatus; real component).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, act, waitFor } from '@testing-library/react';

vi.mock('../api/client', () => ({
  api: {
    getActiveCidr: vi.fn(),
    triggerScan: vi.fn(),
  },
}));

vi.mock('../hooks/useScanStatus', () => ({
  useScanStatus: () => null,
}));

import { api } from '../api/client';
import type { ScanRequest } from '../api/types';
import { ScanTriggerForm } from '../components/ScanTriggerForm';

const mockGetActiveCidr = api.getActiveCidr as ReturnType<typeof vi.fn>;
const mockTriggerScan = api.triggerScan as ReturnType<typeof vi.fn>;

/** Render the form and let the getActiveCidr mount effect settle. */
async function renderSettled() {
  render(<ScanTriggerForm />);
  await waitFor(() => {
    expect(mockGetActiveCidr).toHaveBeenCalled();
  });
  await act(async () => {
    await Promise.resolve();
  });
}

/** Switch the scan-type select to the given type. */
function selectType(type: string) {
  fireEvent.change(screen.getByRole('combobox'), { target: { value: type } });
}

describe('ScanTriggerForm — Skip host discovery checkbox', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Empty active-cidr shape → form keeps its default CIDR (192.168.1.0/24).
    mockGetActiveCidr.mockResolvedValue({
      iface: null,
      cidr: null,
      ipAddress: null,
      prefix: 0,
    });
    mockTriggerScan.mockResolvedValue({ id: 1 });
  });

  // -------------------------------------------------------------------------
  // Case 1 — SERVICE_DETECT: checkbox exists, labeled exactly, unchecked
  // -------------------------------------------------------------------------
  it('renders a checkbox labeled "Skip host discovery" (unchecked) when SERVICE_DETECT is selected', async () => {
    await renderSettled();
    selectType('SERVICE_DETECT');

    const checkbox = screen.getByRole('checkbox', { name: 'Skip host discovery' });
    expect(checkbox).toBeInTheDocument();
    expect((checkbox as HTMLInputElement).checked).toBe(false);
  });

  // -------------------------------------------------------------------------
  // Case 2 — checkbox is ABSENT for non-SERVICE_DETECT types
  // -------------------------------------------------------------------------
  it('does NOT render the checkbox when PING_SWEEP (default) is selected', async () => {
    await renderSettled();

    expect(
      screen.queryByRole('checkbox', { name: 'Skip host discovery' })
    ).not.toBeInTheDocument();
  });

  it('does NOT render the checkbox when OS_FINGERPRINT is selected', async () => {
    await renderSettled();
    selectType('OS_FINGERPRINT');

    expect(
      screen.queryByRole('checkbox', { name: 'Skip host discovery' })
    ).not.toBeInTheDocument();
  });

  // -------------------------------------------------------------------------
  // Case 3 — SERVICE_DETECT, UNCHECKED submit: body has NO skipHostDiscovery key
  // -------------------------------------------------------------------------
  it('omits the skipHostDiscovery key entirely from the submit body when unchecked (default)', async () => {
    await renderSettled();
    selectType('SERVICE_DETECT');

    const checkbox = screen.getByRole('checkbox', { name: 'Skip host discovery' });
    expect((checkbox as HTMLInputElement).checked).toBe(false);

    fireEvent.click(screen.getByRole('button', { name: /^Scan$/i }));

    await waitFor(() => {
      expect(mockTriggerScan).toHaveBeenCalledTimes(1);
    });

    const body = mockTriggerScan.mock.calls[0][0];
    expect(body).toHaveProperty('cidr', '192.168.1.0/24');
    expect(body).toHaveProperty('type', 'SERVICE_DETECT');
    // The key must be ABSENT — not present-as-false, not present-as-undefined.
    expect(body).not.toHaveProperty('skipHostDiscovery');
  });

  // -------------------------------------------------------------------------
  // Case 4 — SERVICE_DETECT, CHECKED submit: skipHostDiscovery: true + cidr/type
  // -------------------------------------------------------------------------
  it('sends skipHostDiscovery: true alongside cidr/type when checked', async () => {
    await renderSettled();
    selectType('SERVICE_DETECT');

    const checkbox = screen.getByRole('checkbox', { name: 'Skip host discovery' });
    fireEvent.click(checkbox);
    expect((checkbox as HTMLInputElement).checked).toBe(true);

    fireEvent.click(screen.getByRole('button', { name: /^Scan$/i }));

    await waitFor(() => {
      expect(mockTriggerScan).toHaveBeenCalledTimes(1);
    });

    const expected: ScanRequest = {
      cidr: '192.168.1.0/24',
      type: 'SERVICE_DETECT',
      skipHostDiscovery: true,
    };
    expect(mockTriggerScan).toHaveBeenCalledWith(expected);
  });

  // -------------------------------------------------------------------------
  // Case 5 — check then uncheck round-trip: key is dropped again (not false)
  // -------------------------------------------------------------------------
  it('drops the key again (does not send skipHostDiscovery: false) after check → uncheck', async () => {
    await renderSettled();
    selectType('SERVICE_DETECT');

    const checkbox = screen.getByRole('checkbox', { name: 'Skip host discovery' });
    fireEvent.click(checkbox); // check
    fireEvent.click(checkbox); // uncheck
    expect((checkbox as HTMLInputElement).checked).toBe(false);

    fireEvent.click(screen.getByRole('button', { name: /^Scan$/i }));

    await waitFor(() => {
      expect(mockTriggerScan).toHaveBeenCalledTimes(1);
    });

    const body = mockTriggerScan.mock.calls[0][0];
    expect(body).not.toHaveProperty('skipHostDiscovery');
  });

  // -------------------------------------------------------------------------
  // Case 6 — checked under SERVICE_DETECT, then type switched away: checkbox
  // disappears and the submitted body must NOT carry the key.
  // -------------------------------------------------------------------------
  it('does not send the key after switching the type away from SERVICE_DETECT with the box checked', async () => {
    await renderSettled();
    selectType('SERVICE_DETECT');

    fireEvent.click(screen.getByRole('checkbox', { name: 'Skip host discovery' }));
    selectType('PING_SWEEP');

    expect(
      screen.queryByRole('checkbox', { name: 'Skip host discovery' })
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Scan$/i }));

    await waitFor(() => {
      expect(mockTriggerScan).toHaveBeenCalledTimes(1);
    });

    const body = mockTriggerScan.mock.calls[0][0];
    expect(body).toHaveProperty('type', 'PING_SWEEP');
    expect(body).not.toHaveProperty('skipHostDiscovery');
  });
});
