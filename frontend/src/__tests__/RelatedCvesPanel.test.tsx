import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { RelatedCvesPanel } from '../components/RelatedCvesPanel';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    listFleetCves: vi.fn(),
    cveDetail: vi.fn(),
  },
}));

const makeSummary = (cveId: string, cvss: string, kev: boolean) => ({
  cveId,
  published: '2024-01-01T00:00:00Z',
  lastModified: '2024-01-02T00:00:00Z',
  vulnStatus: 'Analyzed',
  description: `desc-${cveId}`,
  cvssV31Score: cvss,
  cvssV31Vector: 'CVSS:3.1/AV:N/AC:L',
  cvssV30Score: null,
  cvssV30Vector: null,
  cvssV2Score: null,
  cvssV2Vector: null,
  fetchedAt: null,
  kev,
  epssScore: '0.1',
  compositeScore: cvss,
});

const makePage = (content: ReturnType<typeof makeSummary>[]) => ({
  content,
  totalElements: content.length,
  totalPages: 1,
  number: 0,
  size: 50,
});

const makeDetail = (cveId: string, description: string) => ({
  cveId,
  published: '2024-01-01T00:00:00Z',
  lastModified: '2024-01-02T00:00:00Z',
  vulnStatus: 'Analyzed',
  description,
  cvssV31Score: '8.0',
  cvssV31Vector: 'CVSS:3.1/AV:N/AC:L',
  cvssV30Score: null,
  cvssV30Vector: null,
  cvssV2Score: null,
  cvssV2Vector: null,
  fetchedAt: null,
  rawJson: null,
  kev: false,
  epssScore: '0.1',
  compositeScore: '8.0',
});

describe('<RelatedCvesPanel />', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders empty-state copy when api returns zero content', async () => {
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(makePage([]));
    render(<RelatedCvesPanel deviceId={42} hostname="host-42" ipAddress="10.0.0.42" />);
    const empty = await screen.findByTestId('related-cves-empty');
    expect(empty).toHaveTextContent('No linked CVEs for this threat.');
  });

  it('renders one row per matched cve when api returns content', async () => {
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([
        makeSummary('CVE-2024-0001', '8.5', false),
        makeSummary('CVE-2024-0002', '5.0', false),
        makeSummary('CVE-2024-0003', '3.0', false),
      ]),
    );
    render(<RelatedCvesPanel deviceId={1} hostname="host-1" ipAddress="10.0.0.1" />);
    const firstRow = await screen.findByTestId('related-cves-row-CVE-2024-0001');
    expect(firstRow).toHaveTextContent('CVE-2024-0001');
    const secondRow = screen.getByTestId('related-cves-row-CVE-2024-0002');
    expect(secondRow).toBeInTheDocument();
    expect(secondRow).toHaveTextContent('CVE-2024-0002');
    const thirdRow = screen.getByTestId('related-cves-row-CVE-2024-0003');
    expect(thirdRow).toBeInTheDocument();
    expect(thirdRow).toHaveTextContent('CVE-2024-0003');
  });

  it('renders kev badge when cve kev is true', async () => {
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([
        makeSummary('CVE-KEV', '8.5', true),
        makeSummary('CVE-NORMAL', '5.0', false),
      ]),
    );
    render(<RelatedCvesPanel deviceId={1} hostname="host-1" ipAddress="10.0.0.1" />);
    await screen.findByTestId('related-cves-row-CVE-KEV');
    expect(screen.getByTestId('related-cves-kev-badge-CVE-KEV')).toBeInTheDocument();
    expect(screen.queryByTestId('related-cves-kev-badge-CVE-NORMAL')).toBeNull();
  });

  it('lazy-fetches cve detail on row click', async () => {
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([makeSummary('CVE-2024-0001', '8.5', false)]),
    );
    (api.cveDetail as ReturnType<typeof vi.fn>).mockResolvedValue(
      makeDetail('CVE-2024-0001', 'Test description'),
    );
    render(<RelatedCvesPanel deviceId={1} hostname="host-1" ipAddress="10.0.0.1" />);
    const row = await screen.findByTestId('related-cves-row-CVE-2024-0001');
    fireEvent.click(row);
    await waitFor(() => expect(api.cveDetail).toHaveBeenCalledTimes(1));
    expect(api.cveDetail).toHaveBeenCalledWith('CVE-2024-0001');
    const detail = await screen.findByTestId('related-cves-detail-CVE-2024-0001');
    expect(detail).toHaveTextContent('Test description');
  });

  it('keyboard enter on row triggers detail lazy fetch', async () => {
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([makeSummary('CVE-2024-0001', '8.5', false)]),
    );
    (api.cveDetail as ReturnType<typeof vi.fn>).mockResolvedValue(
      makeDetail('CVE-2024-0001', 'Test description'),
    );
    render(<RelatedCvesPanel deviceId={1} hostname="host-1" ipAddress="10.0.0.1" />);
    const row = await screen.findByTestId('related-cves-row-CVE-2024-0001');
    fireEvent.keyDown(row, { key: 'Enter' });
    await waitFor(() => expect(api.cveDetail).toHaveBeenCalledTimes(1));
  });

  it('renders error message when list fleet cves rejects', async () => {
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('boom'));
    render(<RelatedCvesPanel deviceId={1} hostname="host-1" ipAddress="10.0.0.1" />);
    await screen.findByText(/boom/);
  });
});
