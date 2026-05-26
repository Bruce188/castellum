import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { StixExportPanel } from '../components/StixExportPanel';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    exportStixBundle: vi.fn(),
  },
}));

const exportStixBundle = vi.mocked(api.exportStixBundle);

beforeEach(() => {
  exportStixBundle.mockReset();
  // jsdom does not implement URL.createObjectURL — stub it.
  if (typeof URL.createObjectURL !== 'function') {
    Object.defineProperty(URL, 'createObjectURL', {
      value: vi.fn(() => 'blob:mock'),
      writable: true,
    });
    Object.defineProperty(URL, 'revokeObjectURL', {
      value: vi.fn(),
      writable: true,
    });
  } else {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock');
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
  }
});

describe('<StixExportPanel />', () => {
  it('VIEWER sees the ADMIN-required notice and no download button', () => {
    render(<StixExportPanel isAdmin={false} />);
    expect(screen.getByText(/ADMIN role required/i)).toBeInTheDocument();
    expect(screen.queryByTestId('stix-download-btn')).toBeNull();
  });

  it('ADMIN can click download and triggers anchor with download attribute', async () => {
    exportStixBundle.mockResolvedValueOnce(
      new Blob([JSON.stringify({ type: 'bundle' })], { type: 'application/json' })
    );

    const appendSpy = vi.spyOn(document.body, 'appendChild');

    render(<StixExportPanel isAdmin={true} />);
    fireEvent.click(screen.getByTestId('stix-download-btn'));

    await waitFor(() => expect(exportStixBundle).toHaveBeenCalledTimes(1));

    // Confirm an anchor with download="…stix-bundle.json" was appended at click time.
    const downloadAnchor = appendSpy.mock.calls.find(([el]) =>
      el instanceof HTMLAnchorElement && el.download.endsWith('.json'));
    expect(downloadAnchor).toBeTruthy();
    const anchor = downloadAnchor![0] as HTMLAnchorElement;
    expect(anchor.download).toMatch(/stix-bundle\.json$/);
    expect(anchor.href).toContain('blob:');

    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(/Downloaded/));
  });

  it('surfaces an error message when export fails', async () => {
    exportStixBundle.mockRejectedValueOnce(new Error('500 Server Error'));
    render(<StixExportPanel isAdmin={true} />);
    fireEvent.click(screen.getByTestId('stix-download-btn'));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/500/));
  });
});
