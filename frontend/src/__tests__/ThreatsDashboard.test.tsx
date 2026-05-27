import { describe, it, expect, beforeEach, beforeAll, afterAll, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ThreatsDashboard } from '../components/ThreatsDashboard';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    topRisk: vi.fn(),
    feedsStatus: vi.fn(),
    listFleetCves: vi.fn(),
    cveDetail: vi.fn(),
  },
}));

const NOW = new Date('2026-05-25T12:00:00Z').getTime();

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

describe('<ThreatsDashboard />', () => {
  beforeAll(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.setSystemTime(NOW);
  });
  afterAll(() => {
    vi.useRealTimers();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows loading state then top-10 table on success', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'host-1', ipAddress: '10.0.0.1', criticality: 'HIGH', score: '8.50', kevCount: 1 },
      { deviceId: 2, hostname: null, ipAddress: '10.0.0.2', criticality: 'MEDIUM', score: '6.30', kevCount: 0 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    render(<ThreatsDashboard />);
    await screen.findByText('host-1');
    expect(screen.getByText('8.50')).toBeInTheDocument();
    expect(screen.getByText('HIGH')).toBeInTheDocument();
    // Device with null hostname falls back to ipAddress
    expect(screen.getByText('10.0.0.2')).toBeInTheDocument();
    expect(screen.getByText('6.30')).toBeInTheDocument();
  });

  it('renders KEV-flagged total across the fleet', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'h1', ipAddress: '10.0.0.1', criticality: 'HIGH', score: '8.50', kevCount: 2 },
      { deviceId: 2, hostname: 'h2', ipAddress: '10.0.0.2', criticality: 'MEDIUM', score: '6.30', kevCount: 3 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: null, rowCount: 0 },
      kev: { lastIngestedAt: null, entryCount: 0 },
      nvd: { lastModified: null, rowCount: 0 },
    });

    render(<ThreatsDashboard />);
    await screen.findByText(/KEV-flagged CVEs/i);
    // 2 + 3 = 5
    const kevBlock = screen.getByText(/KEV-flagged CVEs/i).parentElement!;
    expect(kevBlock.textContent).toContain('5');
  });

  it('renders green freshness badge when feeds are fresh (<7d)', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    render(<ThreatsDashboard />);
    const badge = await screen.findByTestId('freshness-badge');
    expect(badge.className).toMatch(/green/);
  });

  it('renders amber freshness badge for 7-30 day-old EPSS', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-10', rowCount: 100 }, // 15 days old
      kev: { lastIngestedAt: '2026-05-10T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-10T00:00:00Z', rowCount: 42 },
    });

    render(<ThreatsDashboard />);
    const badge = await screen.findByTestId('freshness-badge');
    expect(badge.className).toMatch(/yellow|amber/);
  });

  it('renders red freshness badge when EPSS scoreDate is null', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: null, rowCount: 0 },
      kev: { lastIngestedAt: null, entryCount: 0 },
      nvd: { lastModified: null, rowCount: 0 },
    });

    render(<ThreatsDashboard />);
    const badge = await screen.findByTestId('freshness-badge');
    expect(badge.className).toMatch(/red/);
  });

  it('shows empty state when topRisk returns []', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    render(<ThreatsDashboard />);
    await waitFor(() => screen.getByText(/No devices ranked/i));
  });

  it('expands the related-CVEs panel in place when a row is clicked', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 42, hostname: 'host-42', ipAddress: '10.0.0.42', criticality: 'HIGH', score: '9.10', kevCount: 1 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(makePage([]));

    render(<ThreatsDashboard />);
    const row = await screen.findByTestId('threats-row-42');
    fireEvent.click(row);
    await screen.findByTestId('threats-related-panel-42');
  });

  it('expands the panel on Enter and Space keydown', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 7, hostname: 'host-7', ipAddress: '10.0.0.7', criticality: 'HIGH', score: '7.10', kevCount: 0 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(makePage([]));

    render(<ThreatsDashboard />);
    const row = await screen.findByTestId('threats-row-7');

    fireEvent.keyDown(row, { key: 'Enter' });
    await screen.findByTestId('threats-related-panel-7');

    fireEvent.keyDown(row, { key: 'Enter' });
    await waitFor(() => expect(screen.queryByTestId('threats-related-panel-7')).toBeNull());

    fireEvent.keyDown(row, { key: ' ' });
    await screen.findByTestId('threats-related-panel-7');
  });

  it('shows error message when topRisk fails', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('boom'));
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: null, rowCount: 0 },
      kev: { lastIngestedAt: null, entryCount: 0 },
      nvd: { lastModified: null, rowCount: 0 },
    });

    render(<ThreatsDashboard />);
    await waitFor(() => screen.getByText(/boom/));
  });

  it('panel_rendersEmptyStateCopy_whenDeviceHasNoLinkedCves', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 11, hostname: 'host-11', ipAddress: '10.0.0.11', criticality: 'LOW', score: '0.00', kevCount: 0 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(makePage([]));

    render(<ThreatsDashboard />);
    const row = await screen.findByTestId('threats-row-11');
    fireEvent.click(row);
    const empty = await screen.findByText('No linked CVEs for this threat.');
    expect(empty).toBeInTheDocument();
  });

  it('panel_rendersMatchedCves_whenListFleetCvesReturnsContent', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 22, hostname: 'host-22', ipAddress: '10.0.0.22', criticality: 'HIGH', score: '8.50', kevCount: 1 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([
        makeSummary('CVE-2024-0001', '8.5', true),
        makeSummary('CVE-2024-0002', '5.0', false),
      ]),
    );

    render(<ThreatsDashboard />);
    const row = await screen.findByTestId('threats-row-22');
    fireEvent.click(row);

    await screen.findByTestId('threats-related-panel-22');
    expect(screen.getByTestId('related-cves-row-CVE-2024-0001')).toBeInTheDocument();
    expect(screen.getByTestId('related-cves-row-CVE-2024-0002')).toBeInTheDocument();
    expect(screen.getByTestId('related-cves-kev-badge-CVE-2024-0001')).toBeInTheDocument();
  });

  it('panel_viewAllLink_pointsToCvesPageWithDeviceIdFilter', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 42, hostname: 'host-42', ipAddress: '10.0.0.42', criticality: 'HIGH', score: '8.50', kevCount: 0 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([makeSummary('CVE-2024-0001', '8.5', false)]),
    );

    render(<ThreatsDashboard />);
    const row = await screen.findByTestId('threats-row-42');
    fireEvent.click(row);

    await screen.findByTestId('threats-related-panel-42');
    const viewAll = screen.getByTestId('related-cves-view-all') as HTMLAnchorElement;
    expect(viewAll.getAttribute('href')).toBe('/cves?deviceId=42');
  });

  it('panel_clickingSecondRow_collapsesFirstAndExpandsSecond', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'h1', ipAddress: '10.0.0.1', criticality: 'HIGH', score: '8.50', kevCount: 1 },
      { deviceId: 2, hostname: 'h2', ipAddress: '10.0.0.2', criticality: 'MEDIUM', score: '5.00', kevCount: 0 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(makePage([]));

    render(<ThreatsDashboard />);
    const row1 = await screen.findByTestId('threats-row-1');
    const row2 = await screen.findByTestId('threats-row-2');

    fireEvent.click(row1);
    await screen.findByTestId('threats-related-panel-1');

    fireEvent.click(row2);
    await screen.findByTestId('threats-related-panel-2');
    expect(screen.queryByTestId('threats-related-panel-1')).toBeNull();
  });
});
