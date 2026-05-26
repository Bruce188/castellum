import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { CveEvidenceTable } from '../components/CveEvidenceTable';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    cveDetail: vi.fn(),
  },
}));

const detailFor = (cveId: string, cvss: string, fields: Partial<{ description: string; lastModified: string; published: string }> = {}) => ({
  cveId,
  published: fields.published ?? '2020-07-20T22:15:00Z',
  lastModified: fields.lastModified ?? '2024-01-01T00:00:00Z',
  vulnStatus: 'Analyzed',
  description: fields.description ?? `Description for ${cveId}`,
  cvssV31Score: cvss,
  cvssV31Vector: 'CVSS:3.1/AV:N/AC:L',
  cvssV30Score: null,
  cvssV30Vector: null,
  cvssV2Score: null,
  cvssV2Vector: null,
  fetchedAt: null,
  rawJson: null,
});

describe('<CveEvidenceTable />', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders nothing visible when cveIds is empty', () => {
    render(<CveEvidenceTable cveIds={[]} />);
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    expect(screen.getByText(/No matched CVEs/i)).toBeInTheDocument();
  });

  it('renders one row per CVE id', () => {
    render(<CveEvidenceTable cveIds={['CVE-2020-15778', 'CVE-2020-14145']} />);
    expect(screen.getByText('CVE-2020-15778')).toBeInTheDocument();
    expect(screen.getByText('CVE-2020-14145')).toBeInTheDocument();
  });

  it('expands a row and fetches detail on click; second click uses cache', async () => {
    (api.cveDetail as ReturnType<typeof vi.fn>).mockResolvedValue(detailFor('CVE-2020-15778', '7.8'));
    render(<CveEvidenceTable cveIds={['CVE-2020-15778']} />);

    fireEvent.click(screen.getByText('CVE-2020-15778'));
    await waitFor(() => screen.getByText(/Description for CVE-2020-15778/));
    expect(api.cveDetail).toHaveBeenCalledTimes(1);

    // Collapse
    fireEvent.click(screen.getByText('CVE-2020-15778'));
    // Re-expand — should hit cache, no second fetch
    fireEvent.click(screen.getByText('CVE-2020-15778'));
    await waitFor(() => screen.getByText(/Description for CVE-2020-15778/));
    expect(api.cveDetail).toHaveBeenCalledTimes(1);
  });

  it('shows CVSS score after fetch completes', async () => {
    (api.cveDetail as ReturnType<typeof vi.fn>).mockResolvedValue(detailFor('CVE-2020-15778', '9.1'));
    render(<CveEvidenceTable cveIds={['CVE-2020-15778']} />);
    fireEvent.click(screen.getByText('CVE-2020-15778'));
    await waitFor(() => screen.getByText('9.1'));
  });

  it('sorts by CVSS descending when CVSS column header is clicked', async () => {
    (api.cveDetail as ReturnType<typeof vi.fn>).mockImplementation((id: string) => {
      if (id === 'CVE-A') return Promise.resolve(detailFor('CVE-A', '4.5'));
      if (id === 'CVE-B') return Promise.resolve(detailFor('CVE-B', '9.8'));
      return Promise.resolve(detailFor(id, '7.0'));
    });
    render(<CveEvidenceTable cveIds={['CVE-A', 'CVE-B']} />);
    // Trigger fetches by expanding both, then collapsing
    fireEvent.click(screen.getByText('CVE-A'));
    await waitFor(() => screen.getByText('4.5'));
    fireEvent.click(screen.getByText('CVE-A'));
    fireEvent.click(screen.getByText('CVE-B'));
    await waitFor(() => screen.getByText('9.8'));
    fireEvent.click(screen.getByText('CVE-B'));

    // After both details cached, click CVSS sort header
    const sortHeader = screen.getByRole('button', { name: /CVSS/ });
    fireEvent.click(sortHeader);

    const rows = screen.getAllByRole('row');
    // header row is rows[0]; first data row is rows[1]
    // After descending sort by CVSS, CVE-B (9.8) should precede CVE-A (4.5)
    expect(rows[1].textContent).toContain('CVE-B');
    expect(rows[2].textContent).toContain('CVE-A');
  });

  it('renders KEV chip when row indicates KEV', async () => {
    // Render passes kev hint via prop map
    const kevSet = new Set<string>(['CVE-KEV']);
    render(<CveEvidenceTable cveIds={['CVE-KEV', 'CVE-NORMAL']} kevIds={kevSet} />);
    const kevCell = screen.getAllByTestId('kev-cell');
    expect(kevCell[0].textContent).toContain('KEV');
    expect(kevCell[1].textContent).not.toContain('KEV');
  });

  it('shows error if fetch fails', async () => {
    (api.cveDetail as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('not found'));
    render(<CveEvidenceTable cveIds={['CVE-X']} />);
    fireEvent.click(screen.getByText('CVE-X'));
    await waitFor(() => screen.getByText(/not found/));
  });
});
