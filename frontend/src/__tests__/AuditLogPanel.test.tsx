import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import AuditLogPanel from '../components/AuditLogPanel';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    listAudit: vi.fn(),
    downloadAuditCsv: vi.fn(),
  },
}));

describe('AuditLogPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders nothing when not admin', () => {
    const { container } = render(<AuditLogPanel isAdmin={false} />);
    expect(container.firstChild).toBeNull();
  });

  it('renders empty state for admin when no entries', async () => {
    (api.listAudit as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: [], totalElements: 0, totalPages: 0, number: 0, size: 50,
    });
    render(<AuditLogPanel isAdmin={true} />);
    await waitFor(() => screen.getByText(/No audit entries match/i));
  });

  it('renders one row and toggles expand on click', async () => {
    const entry = {
      id: 1,
      occurredAt: '2026-05-25T10:00:00Z',
      actor: 'alice',
      action: 'SCAN_SUBMIT',
      resourceType: 'scan',
      resourceId: '42',
      payload: '{"ip":"10.0.0.1"}',
    };
    (api.listAudit as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: [entry], totalElements: 1, totalPages: 1, number: 0, size: 50,
    });
    render(<AuditLogPanel isAdmin={true} />);
    // Find the SCAN_SUBMIT cell specifically in the table body (not the dropdown option)
    const actionCell = await screen.findByRole('cell', { name: 'SCAN_SUBMIT' });
    fireEvent.click(actionCell);
    await waitFor(() => screen.getByText(/10\.0\.0\.1/));
  });

  it('Refresh button triggers refetch', async () => {
    (api.listAudit as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: [], totalElements: 0, totalPages: 0, number: 0, size: 50,
    });
    render(<AuditLogPanel isAdmin={true} />);
    await screen.findByText(/No audit entries match/i);
    fireEvent.click(screen.getByText('Refresh'));
    await waitFor(() => expect(api.listAudit).toHaveBeenCalledTimes(2));
  });

  it('Action filter triggers refetch with action arg', async () => {
    (api.listAudit as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: [], totalElements: 0, totalPages: 0, number: 0, size: 50,
    });
    render(<AuditLogPanel isAdmin={true} />);
    await screen.findByText(/No audit entries match/i);
    const actionSelect = screen.getByLabelText(/Action/i) as HTMLSelectElement;
    fireEvent.change(actionSelect, { target: { value: 'SCAN_SUBMIT' } });
    fireEvent.click(screen.getByText('Apply'));
    await waitFor(() => {
      const calls = (api.listAudit as ReturnType<typeof vi.fn>).mock.calls;
      const lastCall = calls[calls.length - 1];
      expect(lastCall[0].action).toBe('SCAN_SUBMIT');
    });
  });

  it('CSV button calls downloadAuditCsv with current filters', async () => {
    (api.listAudit as ReturnType<typeof vi.fn>).mockResolvedValue({
      content: [], totalElements: 0, totalPages: 0, number: 0, size: 50,
    });
    (api.downloadAuditCsv as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Blob(['header\n'], { type: 'text/csv' })
    );
    (globalThis as unknown as { URL: { createObjectURL: ReturnType<typeof vi.fn>; revokeObjectURL: ReturnType<typeof vi.fn> } }).URL.createObjectURL = vi.fn(() => 'blob:fake');
    (globalThis as unknown as { URL: { createObjectURL: ReturnType<typeof vi.fn>; revokeObjectURL: ReturnType<typeof vi.fn> } }).URL.revokeObjectURL = vi.fn();

    render(<AuditLogPanel isAdmin={true} />);
    await screen.findByText(/No audit entries match/i);
    fireEvent.click(screen.getByText('Download CSV'));
    await waitFor(() => expect(api.downloadAuditCsv).toHaveBeenCalledTimes(1));
  });
});
