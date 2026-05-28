import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { StixExportPanel } from '../components/StixExportPanel';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    exportStixBundle: vi.fn(),
    exportStixBundleText: vi.fn(),
  },
}));

const exportStixBundle = vi.mocked(api.exportStixBundle);
const exportStixBundleText = vi.mocked(api.exportStixBundleText);

beforeEach(() => {
  exportStixBundle.mockReset();
  exportStixBundleText.mockReset();
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

  // ── NEW TESTS (red phase — preview affordance not yet implemented) ──────────

  it('ADMIN can preview the bundle as indented JSON', async () => {
    const compactJson =
      '{"type":"bundle","id":"bundle--x","spec_version":"2.1","objects":[{"type":"identity","id":"identity--1"}]}';
    exportStixBundleText.mockResolvedValueOnce(compactJson);

    render(<StixExportPanel isAdmin={true} />);
    fireEvent.click(screen.getByTestId('stix-preview-btn'));

    await waitFor(() => {
      const pre = screen.getByTestId('stix-preview');
      expect(pre).toBeInTheDocument();
      // Proves client-side indentation happened, not just echoing the compact wire form.
      expect(pre.textContent).toContain('\n  "type": "bundle"');
    });
  });

  it('preview does not trigger a Blob download', async () => {
    const compactJson = '{"type":"bundle","id":"bundle--x","spec_version":"2.1","objects":[]}';
    exportStixBundleText.mockResolvedValueOnce(compactJson);

    const appendSpy = vi.spyOn(document.body, 'appendChild');

    render(<StixExportPanel isAdmin={true} />);
    fireEvent.click(screen.getByTestId('stix-preview-btn'));

    await waitFor(() => expect(screen.getByTestId('stix-preview')).toBeInTheDocument());

    // exportStixBundle (Blob path) must NOT have been called.
    expect(exportStixBundle).not.toHaveBeenCalled();

    // No anchor with a .json download attribute should have been appended.
    const downloadAnchor = appendSpy.mock.calls.find(
      ([el]) => el instanceof HTMLAnchorElement && el.download.endsWith('.json')
    );
    expect(downloadAnchor).toBeUndefined();
  });

  it('raw download still works alongside preview', async () => {
    exportStixBundle.mockResolvedValueOnce(
      new Blob([JSON.stringify({ type: 'bundle' })], { type: 'application/json' })
    );

    const appendSpy = vi.spyOn(document.body, 'appendChild');

    render(<StixExportPanel isAdmin={true} />);
    fireEvent.click(screen.getByTestId('stix-download-btn'));

    await waitFor(() => {
      const downloadAnchor = appendSpy.mock.calls.find(
        ([el]) => el instanceof HTMLAnchorElement && el.download.endsWith('.json')
      );
      expect(downloadAnchor).toBeTruthy();
    });

    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(/Downloaded/i));
  });

  it('VIEWER sees neither preview nor download controls', () => {
    render(<StixExportPanel isAdmin={false} />);
    expect(screen.getByText(/ADMIN role required/i)).toBeInTheDocument();
    expect(screen.queryByTestId('stix-preview-btn')).toBeNull();
    expect(screen.queryByTestId('stix-download-btn')).toBeNull();
  });

  it('surfaces an error when preview fetch fails', async () => {
    exportStixBundleText.mockRejectedValueOnce(new Error('500 Server Error'));

    render(<StixExportPanel isAdmin={true} />);
    fireEvent.click(screen.getByTestId('stix-preview-btn'));

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/500/));
  });
});
