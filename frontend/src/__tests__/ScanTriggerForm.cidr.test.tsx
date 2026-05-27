import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import React from 'react';

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
import { ScanTriggerForm } from '../components/ScanTriggerForm';

const mockGetActiveCidr = api.getActiveCidr as ReturnType<typeof vi.fn>;

describe('ScanTriggerForm CIDR pre-fill', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // -----------------------------------------------------------------------
  // Case 1 — prefills CIDR from detection on mount
  // -----------------------------------------------------------------------
  it('prefills CIDR from active-cidr detection on mount', async () => {
    mockGetActiveCidr.mockResolvedValue({
      iface: 'eth6',
      cidr: '192.168.68.0/22',
      ipAddress: '192.168.68.51',
      prefix: 22,
      note: null,
    });

    render(<ScanTriggerForm />);

    await waitFor(() => {
      const input = screen.getByRole('textbox');
      expect((input as HTMLInputElement).value).toBe('192.168.68.0/22');
    });
  });

  // -----------------------------------------------------------------------
  // Case 2 — field stays editable after pre-fill
  // -----------------------------------------------------------------------
  it('field stays editable after detection pre-fill', async () => {
    mockGetActiveCidr.mockResolvedValue({
      iface: 'eth6',
      cidr: '192.168.68.0/22',
      ipAddress: '192.168.68.51',
      prefix: 22,
      note: null,
    });

    render(<ScanTriggerForm />);

    // Wait for pre-fill
    await waitFor(() => {
      const input = screen.getByRole('textbox');
      expect((input as HTMLInputElement).value).toBe('192.168.68.0/22');
    });

    // User types a different value
    const input = screen.getByRole('textbox');
    fireEvent.change(input, { target: { value: '10.0.0.0/24' } });

    expect((input as HTMLInputElement).value).toBe('10.0.0.0/24');
  });

  // -----------------------------------------------------------------------
  // Case 3 — falls back when detection returns empty shape (cidr: null)
  // -----------------------------------------------------------------------
  it('keeps usable fallback value when detection returns empty shape', async () => {
    mockGetActiveCidr.mockResolvedValue({
      iface: null,
      cidr: null,
      ipAddress: null,
      prefix: 0,
    });

    render(<ScanTriggerForm />);

    // Let the effect settle
    await waitFor(() => {
      // getActiveCidr was called
      expect(mockGetActiveCidr).toHaveBeenCalled();
    });

    // The input should still have a non-empty fallback value (initial state)
    const input = screen.getByRole('textbox');
    expect((input as HTMLInputElement).value).not.toBe('');
  });

  // -----------------------------------------------------------------------
  // Case 4 — renders clamp note when present
  // -----------------------------------------------------------------------
  it('renders clamp note as inline hint when detection returns a note', async () => {
    const note = 'Detected /16 narrowed to /22 (scan size cap) — adjust if needed.';
    mockGetActiveCidr.mockResolvedValue({
      iface: 'eth0',
      cidr: '192.168.0.0/22',
      ipAddress: '192.168.0.51',
      prefix: 22,
      note,
    });

    render(<ScanTriggerForm />);

    await waitFor(() => {
      expect(screen.getByText(note)).toBeDefined();
    });
  });
});
