import { StrictMode } from 'react';
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
    const deviceId = 7;
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([
        makeSummary('CVE-2024-0001', '8.5', false),
        makeSummary('CVE-2024-0002', '5.0', false),
        makeSummary('CVE-2024-0003', '3.0', false),
      ]),
    );
    render(<RelatedCvesPanel deviceId={deviceId} hostname="host-1" ipAddress="10.0.0.1" />);
    const firstRow = await screen.findByTestId('related-cves-row-CVE-2024-0001');
    expect(firstRow).toHaveTextContent('CVE-2024-0001');
    const secondRow = screen.getByTestId('related-cves-row-CVE-2024-0002');
    expect(secondRow).toBeInTheDocument();
    expect(secondRow).toHaveTextContent('CVE-2024-0002');
    const thirdRow = screen.getByTestId('related-cves-row-CVE-2024-0003');
    expect(thirdRow).toBeInTheDocument();
    expect(thirdRow).toHaveTextContent('CVE-2024-0003');
    // AC1: Locks the full 6-arg call contract. The 5th slot (kevOnly) must be
    // explicitly undefined to reach the 6th sort slot. Dropping 'kev' here
    // causes this test to fail — the assertion is falsifiable.
    expect(api.listFleetCves).toHaveBeenCalledWith(0, 50, undefined, deviceId, undefined, 'kev');
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

  it('keyboard enter and space on row both trigger detail lazy fetch', async () => {
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([makeSummary('CVE-2024-0001', '8.5', false)]),
    );
    (api.cveDetail as ReturnType<typeof vi.fn>).mockResolvedValue(
      makeDetail('CVE-2024-0001', 'Test description'),
    );
    render(<RelatedCvesPanel deviceId={1} hostname="host-1" ipAddress="10.0.0.1" />);
    const row = await screen.findByTestId('related-cves-row-CVE-2024-0001');

    // Enter expands and triggers cveDetail fetch (1)
    fireEvent.keyDown(row, { key: 'Enter' });
    await waitFor(() => expect(api.cveDetail).toHaveBeenCalledTimes(1));
    expect(row).toHaveAttribute('aria-expanded', 'true');

    // Enter again collapses; cached 'ok' status means no refetch
    fireEvent.keyDown(row, { key: 'Enter' });
    await waitFor(() => expect(row).toHaveAttribute('aria-expanded', 'false'));

    // Space re-expands; cache hit, still only one fetch overall
    fireEvent.keyDown(row, { key: ' ' });
    await waitFor(() => expect(row).toHaveAttribute('aria-expanded', 'true'));
    expect(api.cveDetail).toHaveBeenCalledTimes(1);
  });

  it('keyboard space on a cold row triggers detail lazy fetch', async () => {
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([makeSummary('CVE-2024-0001', '8.5', false)]),
    );
    (api.cveDetail as ReturnType<typeof vi.fn>).mockResolvedValue(
      makeDetail('CVE-2024-0001', 'Test description'),
    );
    render(<RelatedCvesPanel deviceId={1} hostname="host-1" ipAddress="10.0.0.1" />);
    const row = await screen.findByTestId('related-cves-row-CVE-2024-0001');
    // Space is the very first interaction — exercises the cold-cache path
    // without an Enter warming it first.
    fireEvent.keyDown(row, { key: ' ' });
    await waitFor(() => expect(api.cveDetail).toHaveBeenCalledTimes(1));
    expect(row).toHaveAttribute('aria-expanded', 'true');
    expect(api.cveDetail).toHaveBeenCalledWith('CVE-2024-0001');
  });

  it('renders error sub-row when cveDetail rejects', async () => {
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([makeSummary('CVE-2024-0001', '8.5', false)]),
    );
    (api.cveDetail as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('boom'));
    render(<RelatedCvesPanel deviceId={1} hostname="host-1" ipAddress="10.0.0.1" />);
    const row = await screen.findByTestId('related-cves-row-CVE-2024-0001');
    fireEvent.click(row);
    const detail = await screen.findByTestId('related-cves-detail-CVE-2024-0001');
    const errorDiv = await screen.findByText('boom');
    expect(detail).toContainElement(errorDiv);
    expect(errorDiv).toHaveClass('text-red-600');
  });

  it('renders error message when list fleet cves rejects', async () => {
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('boom'));
    render(<RelatedCvesPanel deviceId={1} hostname="host-1" ipAddress="10.0.0.1" />);
    const errorEl = await screen.findByText(/boom/);
    expect(errorEl).toHaveClass('text-red-600');
  });

  // AC3: KEV-first ordering contract.
  // The mock resolves rows in the order the real backend would return for
  // sort=kev: all KEV-flagged entries first, then non-KEV entries, with
  // cveId ASC as the tiebreak within each tier.
  // The test asserts the rendered DOM row order — NOT merely badge presence.
  it('renders kev-flagged cves before non-kev cves when api returns kev-first order', async () => {
    const deviceId = 11;
    // Mixed-KEV fixture: KEV CVE at lower CVSS (5.0) placed before non-KEV
    // at higher CVSS (9.0), mirroring sort=kev backend output.
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([
        makeSummary('CVE-2024-KEV-1', '5.0', true),
        makeSummary('CVE-2024-NON-1', '9.0', false),
      ]),
    );
    const { container } = render(
      <RelatedCvesPanel deviceId={deviceId} hostname="host-11" ipAddress="10.0.0.11" />,
    );

    // Wait until the list is rendered.
    await screen.findByTestId('related-cves-row-CVE-2024-KEV-1');

    // AC1 contract: sort='kev' arg was passed.
    expect(api.listFleetCves).toHaveBeenCalledWith(0, 50, undefined, deviceId, undefined, 'kev');

    // AC3 contract: DOM order places the KEV row before the non-KEV row.
    const rows = container.querySelectorAll('[data-testid^="related-cves-row-"]');
    expect(rows).toHaveLength(2);
    // First rendered row must be the KEV-flagged one (lower CVSS, but KEV).
    expect(rows[0]).toHaveAttribute('data-testid', 'related-cves-row-CVE-2024-KEV-1');
    expect(rows[0]).toHaveTextContent('CVE-2024-KEV-1');
    // Second rendered row is the high-CVSS non-KEV one.
    expect(rows[1]).toHaveAttribute('data-testid', 'related-cves-row-CVE-2024-NON-1');
    expect(rows[1]).toHaveTextContent('CVE-2024-NON-1');
  });

  // Regression guard: all-non-KEV case still renders without crash.
  it('renders all rows when no cves are kev-flagged', async () => {
    const deviceId = 12;
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([
        makeSummary('CVE-2024-A', '9.0', false),
        makeSummary('CVE-2024-B', '6.0', false),
      ]),
    );
    const { container } = render(
      <RelatedCvesPanel deviceId={deviceId} hostname="host-12" ipAddress="10.0.0.12" />,
    );
    await screen.findByTestId('related-cves-row-CVE-2024-A');
    const rows = container.querySelectorAll('[data-testid^="related-cves-row-"]');
    expect(rows).toHaveLength(2);
    // No KEV badges should be present.
    expect(container.querySelectorAll('[data-testid^="related-cves-kev-badge-"]')).toHaveLength(0);
  });

  // Regression guard: empty-list case still renders without crash.
  it('renders empty state without crash when api returns no cves', async () => {
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(makePage([]));
    render(<RelatedCvesPanel deviceId={13} hostname="host-13" ipAddress="10.0.0.13" />);
    const empty = await screen.findByTestId('related-cves-empty');
    expect(empty).toHaveTextContent('No linked CVEs for this threat.');
  });

  it('strictmode_doesNotDoubleFireCveDetail_onFirstExpand', async () => {
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([makeSummary('CVE-2024-0001', '8.5', false)]),
    );
    (api.cveDetail as ReturnType<typeof vi.fn>).mockResolvedValue(
      makeDetail('CVE-2024-0001', 'Strict description'),
    );
    render(
      <StrictMode>
        <RelatedCvesPanel deviceId={1} hostname="host-1" ipAddress="10.0.0.1" />
      </StrictMode>,
    );
    const row = await screen.findByTestId('related-cves-row-CVE-2024-0001');
    fireEvent.click(row);
    await waitFor(() => expect(api.cveDetail).toHaveBeenCalledTimes(1));
    // Allow a microtask flush; pre-fix, StrictMode's double-invocation of the
    // setExpanded updater would fire a second request here.
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(api.cveDetail).toHaveBeenCalledTimes(1);
  });

  // ---------------------------------------------------------------------------
  // feat/threats-cve-detail-drawer: onCveSelect callback
  // ---------------------------------------------------------------------------

  it('onCveSelect_calledWithCveId_whenRowIsClicked', async () => {
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([makeSummary('CVE-2024-SEL', '8.0', false)]),
    );
    const onCveSelect = vi.fn();
    render(
      <RelatedCvesPanel
        deviceId={5}
        hostname="host-5"
        ipAddress="10.0.0.5"
        onCveSelect={onCveSelect}
      />,
    );
    const row = await screen.findByTestId('related-cves-row-CVE-2024-SEL');
    fireEvent.click(row);
    expect(onCveSelect).toHaveBeenCalledWith('CVE-2024-SEL');
  });

  it('onCveSelect_calledOnKeyboardEnter', async () => {
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([makeSummary('CVE-2024-KEY', '6.0', false)]),
    );
    const onCveSelect = vi.fn();
    render(
      <RelatedCvesPanel
        deviceId={6}
        hostname="host-6"
        ipAddress="10.0.0.6"
        onCveSelect={onCveSelect}
      />,
    );
    const row = await screen.findByTestId('related-cves-row-CVE-2024-KEY');
    fireEvent.keyDown(row, { key: 'Enter' });
    expect(onCveSelect).toHaveBeenCalledWith('CVE-2024-KEY');
  });

  it('onCveSelect_notRequired_fallsBackToInlineExpand', async () => {
    // When onCveSelect is absent the existing inline-expand behaviour still works
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([makeSummary('CVE-2024-INL', '7.0', false)]),
    );
    (api.cveDetail as ReturnType<typeof vi.fn>).mockResolvedValue(
      makeDetail('CVE-2024-INL', 'Inline detail'),
    );
    render(
      <RelatedCvesPanel deviceId={7} hostname="host-7" ipAddress="10.0.0.7" />,
    );
    const row = await screen.findByTestId('related-cves-row-CVE-2024-INL');
    fireEvent.click(row);
    // Inline expand still renders the detail sub-row
    const detail = await screen.findByTestId('related-cves-detail-CVE-2024-INL');
    expect(detail).toBeInTheDocument();
  });
});

