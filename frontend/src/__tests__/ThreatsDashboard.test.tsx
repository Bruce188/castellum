import { describe, it, expect, beforeEach, beforeAll, afterAll, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, useSearchParams } from 'react-router-dom';
import { ThreatsDashboard } from '../components/ThreatsDashboard';
import { api } from '../api/client';

/** Renders the current URL search string for test assertions. */
function LocationProbe() {
  const [searchParams] = useSearchParams();
  return <div data-testid="location-probe">{searchParams.toString()}</div>;
}

function renderWith(initialPath = '/threats') {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <ThreatsDashboard />
      <LocationProbe />
    </MemoryRouter>
  );
}

vi.mock('../api/client', () => ({
  api: {
    topRisk: vi.fn(),
    feedsStatus: vi.fn(),
    listFleetCves: vi.fn(),
    cveDetail: vi.fn(),
    listAffectedDevices: vi.fn(),
    getDevice: vi.fn(),
    deviceRisk: vi.fn(),
    listServicesForDevice: vi.fn(),
    updateDevice: vi.fn(),
    deleteDevice: vi.fn(),
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
    // Default device-detail fetches to rejection so tests that don't care about
    // device detail don't crash when a row is expanded (fetchDeviceDetail swallows errors).
    (api.getDevice as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('not mocked'));
    (api.deviceRisk as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('not mocked'));
    (api.listServicesForDevice as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('not mocked'));
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

    renderWith();
    await screen.findByText('host-1');
    expect(screen.getByText('8.50')).toBeInTheDocument();
    // HIGH appears in both the criticality select options and the table cell; check at least one is present
    expect(screen.getAllByText('HIGH').length).toBeGreaterThan(0);
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

    renderWith();
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

    renderWith();
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

    renderWith();
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

    renderWith();
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

    renderWith();
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

    renderWith();
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

    renderWith();
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

    renderWith();
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

    renderWith();
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

    renderWith();
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

    renderWith();
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

    renderWith();
    const row1 = await screen.findByTestId('threats-row-1');
    const row2 = await screen.findByTestId('threats-row-2');

    fireEvent.click(row1);
    await screen.findByTestId('threats-related-panel-1');

    fireEvent.click(row2);
    await screen.findByTestId('threats-related-panel-2');
    expect(screen.queryByTestId('threats-related-panel-1')).toBeNull();
  });

  // ---------------------------------------------------------------------------
  // Task 2.1: Sort tests (RED → will go GREEN after component implementation)
  // ---------------------------------------------------------------------------

  it('sort_clickingCompositeHeader_reordersRenderedRowsDescThenAsc', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'host-1', ipAddress: '10.0.0.1', criticality: 'LOW',    score: '5.00', kevCount: 0 },
      { deviceId: 2, hostname: 'host-2', ipAddress: '10.0.0.2', criticality: 'HIGH',   score: '9.00', kevCount: 0 },
      { deviceId: 3, hostname: 'host-3', ipAddress: '10.0.0.3', criticality: 'MEDIUM', score: '7.00', kevCount: 0 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith();
    await screen.findByTestId('threats-row-1');

    // Default: composite DESC → order should be row-2(9), row-3(7), row-1(5)
    let rows = screen.getAllByTestId(/^threats-row-/);
    expect(rows.map(r => r.getAttribute('data-testid'))).toEqual([
      'threats-row-2', 'threats-row-3', 'threats-row-1',
    ]);

    // Click Composite header → flip to ASC
    fireEvent.click(screen.getByTestId('sort-composite'));

    rows = screen.getAllByTestId(/^threats-row-/);
    expect(rows.map(r => r.getAttribute('data-testid'))).toEqual([
      'threats-row-1', 'threats-row-3', 'threats-row-2',
    ]);
  });

  it('sort_clickingHostHeader_reordersRenderedRowsAlphabetically', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'zeta',  ipAddress: '10.0.0.1', criticality: 'LOW',    score: '5.00', kevCount: 0 },
      { deviceId: 2, hostname: 'alpha', ipAddress: '10.0.0.2', criticality: 'MEDIUM', score: '6.00', kevCount: 0 },
      { deviceId: 3, hostname: 'mike',  ipAddress: '10.0.0.3', criticality: 'HIGH',   score: '7.00', kevCount: 0 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith();
    await screen.findByTestId('threats-row-1');

    // Click Host → ascending (default for host)
    fireEvent.click(screen.getByTestId('sort-host'));
    let rows = screen.getAllByTestId(/^threats-row-/);
    expect(rows.map(r => r.getAttribute('data-testid'))).toEqual([
      'threats-row-2', 'threats-row-3', 'threats-row-1',
    ]);

    // Click Host again → descending
    fireEvent.click(screen.getByTestId('sort-host'));
    rows = screen.getAllByTestId(/^threats-row-/);
    expect(rows.map(r => r.getAttribute('data-testid'))).toEqual([
      'threats-row-1', 'threats-row-3', 'threats-row-2',
    ]);
  });

  it('sort_activeHeader_showsDirectionArrow', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'h1', ipAddress: '10.0.0.1', criticality: 'HIGH', score: '8.50', kevCount: 1 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith();
    await screen.findByTestId('threats-row-1');

    // Default: composite active + desc → shows ↓
    const compositeBtn = screen.getByTestId('sort-composite');
    expect(compositeBtn.textContent).toContain('↓');

    // Flip to asc
    fireEvent.click(compositeBtn);
    expect(compositeBtn.textContent).toContain('↑');

    // Click KEV → KEV becomes active with default desc; Composite shows no arrow
    const kevBtn = screen.getByTestId('sort-kev');
    fireEvent.click(kevBtn);
    expect(kevBtn.textContent).toContain('↓');
    expect(compositeBtn.textContent).not.toMatch(/[↑↓]/);
  });

  it('sort_doesNotRefetch', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'h1', ipAddress: '10.0.0.1', criticality: 'HIGH', score: '8.50', kevCount: 1 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith();
    await screen.findByTestId('threats-row-1');

    // Already called once on mount
    expect(api.topRisk).toHaveBeenCalledTimes(1);

    // Click sort header — should NOT trigger a new fetch
    fireEvent.click(screen.getByTestId('sort-kev'));

    expect(api.topRisk).toHaveBeenCalledTimes(1);
  });

  // ---------------------------------------------------------------------------
  // Task 3.1: Filter tests (RED → GREEN after component implementation)
  // ---------------------------------------------------------------------------

  it('filter_kevOnlyToggle_hidesNonKevRows', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'h1', ipAddress: '10.0.0.1', criticality: 'HIGH',   score: '8.50', kevCount: 2 },
      { deviceId: 2, hostname: 'h2', ipAddress: '10.0.0.2', criticality: 'MEDIUM', score: '5.00', kevCount: 0 },
      { deviceId: 3, hostname: 'h3', ipAddress: '10.0.0.3', criticality: 'LOW',    score: '3.00', kevCount: 1 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith();
    await screen.findByTestId('threats-row-1');

    // All 3 rows visible initially
    expect(screen.getByTestId('threats-row-1')).toBeInTheDocument();
    expect(screen.getByTestId('threats-row-2')).toBeInTheDocument();
    expect(screen.getByTestId('threats-row-3')).toBeInTheDocument();

    // Toggle KEV-only
    fireEvent.click(screen.getByTestId('kev-only-toggle'));

    // rows 1 and 3 have kevCount > 0; row 2 (kevCount=0) should be hidden
    expect(screen.getByTestId('threats-row-1')).toBeInTheDocument();
    expect(screen.queryByTestId('threats-row-2')).toBeNull();
    expect(screen.getByTestId('threats-row-3')).toBeInTheDocument();
  });

  it('filter_criticalitySelect_keepsOnlyMatchingRows', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'h1', ipAddress: '10.0.0.1', criticality: 'HIGH',     score: '8.00', kevCount: 0 },
      { deviceId: 2, hostname: 'h2', ipAddress: '10.0.0.2', criticality: 'LOW',      score: '2.00', kevCount: 0 },
      { deviceId: 3, hostname: 'h3', ipAddress: '10.0.0.3', criticality: 'CRITICAL', score: '9.50', kevCount: 1 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith();
    await screen.findByTestId('threats-row-1');

    // Filter to HIGH only
    fireEvent.change(screen.getByTestId('threats-crit-select'), { target: { value: 'HIGH' } });

    expect(screen.getByTestId('threats-row-1')).toBeInTheDocument();
    expect(screen.queryByTestId('threats-row-2')).toBeNull();
    expect(screen.queryByTestId('threats-row-3')).toBeNull();
  });

  it('filter_emptyAfterFilter_rendersDistinctMessage', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'h1', ipAddress: '10.0.0.1', criticality: 'HIGH',   score: '8.00', kevCount: 0 },
      { deviceId: 2, hostname: 'h2', ipAddress: '10.0.0.2', criticality: 'MEDIUM', score: '5.00', kevCount: 0 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith();
    await screen.findByTestId('threats-row-1');

    // Toggle KEV-only — all rows have kevCount=0, so filter result is empty
    fireEvent.click(screen.getByTestId('kev-only-toggle'));

    // Filter-empty message appears; no-data copy must NOT appear
    await screen.findByText(/No threats match these filters/i);
    expect(screen.queryByText(/No devices ranked/i)).toBeNull();
  });

  it('filter_emptyFleet_stillRendersNoDataCopy_notFilterMessage', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith();
    await screen.findByText(/No devices ranked/i);

    expect(screen.queryByText(/No threats match these filters/i)).toBeNull();
  });

  it('filter_hostText_narrowsBySubstring', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'web-prod-1',  ipAddress: '10.0.0.1', criticality: 'HIGH',   score: '8.00', kevCount: 0 },
      { deviceId: 2, hostname: 'db-prod-2',   ipAddress: '10.0.0.2', criticality: 'HIGH',   score: '7.00', kevCount: 0 },
      { deviceId: 3, hostname: null,           ipAddress: '10.0.0.9', criticality: 'MEDIUM', score: '5.00', kevCount: 0 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith();
    await screen.findByTestId('threats-row-1');

    const hostInput = screen.getByTestId('threats-host-filter');

    // Type 'prod' — only the two prod rows should match
    fireEvent.change(hostInput, { target: { value: 'prod' } });
    expect(screen.getByTestId('threats-row-1')).toBeInTheDocument();
    expect(screen.getByTestId('threats-row-2')).toBeInTheDocument();
    expect(screen.queryByTestId('threats-row-3')).toBeNull();

    // Clear — all three return
    fireEvent.change(hostInput, { target: { value: '' } });
    expect(screen.getByTestId('threats-row-1')).toBeInTheDocument();
    expect(screen.getByTestId('threats-row-2')).toBeInTheDocument();
    expect(screen.getByTestId('threats-row-3')).toBeInTheDocument();
  });

  // ---------------------------------------------------------------------------
  // Task 4.1: Row-count selector tests (RED → GREEN after component implementation)
  // ---------------------------------------------------------------------------

  it('limit_changingSelector_refetchesWithNewN', async () => {
    const rows = [
      { deviceId: 1, hostname: 'h1', ipAddress: '10.0.0.1', criticality: 'HIGH' as const, score: '8.50', kevCount: 1 },
    ];
    (api.topRisk as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce(rows)
      .mockResolvedValueOnce(rows);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith();
    await screen.findByTestId('threats-row-1');

    // Initial call with default limit 10
    expect(api.topRisk).toHaveBeenCalledWith(10);

    // Change limit to 25
    fireEvent.change(screen.getByTestId('threats-limit-select'), { target: { value: '25' } });

    await waitFor(() => expect(api.topRisk).toHaveBeenLastCalledWith(25));
  });

  it('limit_defaultIsTen_onInitialMount', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith();
    await screen.findByText(/No devices ranked/i);

    expect(api.topRisk).toHaveBeenCalledWith(10);
    expect((screen.getByTestId('threats-limit-select') as HTMLSelectElement).value).toBe('10');
  });

  it('limit_initialUrlParam_hydratesAndFetches', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith('/threats?limit=50');
    await screen.findByText(/No devices ranked/i);

    expect(api.topRisk).toHaveBeenCalledWith(50);
    expect((screen.getByTestId('threats-limit-select') as HTMLSelectElement).value).toBe('50');
  });

  it('limit_refetch_preservesArrayCollapse', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce([
        { deviceId: 1, hostname: 'h1', ipAddress: '10.0.0.1', criticality: 'HIGH' as const, score: '8.50', kevCount: 0 },
      ])
      // Second call (after changing limit) returns non-array — should collapse to empty
      .mockResolvedValueOnce(null as unknown as import('../api/types').TopRiskDeviceDto[]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith();
    await screen.findByTestId('threats-row-1');

    // Change limit — triggers second fetch that returns null
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    fireEvent.change(screen.getByTestId('threats-limit-select'), { target: { value: '25' } });

    // Should render no-data empty state (Array.isArray collapses null → [])
    await screen.findByText(/No devices ranked/i);
  });

  // ---------------------------------------------------------------------------
  // Task 5.1: URL binding round-trip tests (RED → GREEN after component impl)
  // ---------------------------------------------------------------------------

  it('url_initialParams_hydrateAllControls', async () => {
    // Seed a row that has kevCount>0 AND criticality=HIGH so it survives crit=HIGH+kevOnly filters
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'db-server', ipAddress: '10.0.0.1', criticality: 'HIGH' as const, score: '8.50', kevCount: 1 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith('/threats?sort=kev&dir=asc&crit=HIGH&kevOnly=true&limit=25&host=db');
    await screen.findByTestId('threats-row-1');

    // sort=kev, dir=asc → KEV header should show ↑
    expect(screen.getByTestId('sort-kev').textContent).toContain('↑');
    // Composite header should have no arrow (not active)
    expect(screen.getByTestId('sort-composite').textContent).not.toMatch(/[↑↓]/);
    // criticality select = HIGH
    expect((screen.getByTestId('threats-crit-select') as HTMLSelectElement).value).toBe('HIGH');
    // kev-only-toggle = pressed
    expect(screen.getByTestId('kev-only-toggle').getAttribute('aria-pressed')).toBe('true');
    // limit select = 25
    expect((screen.getByTestId('threats-limit-select') as HTMLSelectElement).value).toBe('25');
    // host input = 'db'
    expect((screen.getByTestId('threats-host-filter') as HTMLInputElement).value).toBe('db');
    // api called with limit=25
    expect(api.topRisk).toHaveBeenCalledWith(25);
  });

  it('url_togglingSort_reflectsSortAndDirParams', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 1, hostname: 'h1', ipAddress: '10.0.0.1', criticality: 'HIGH' as const, score: '8.50', kevCount: 1 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith();
    await screen.findByTestId('threats-row-1');

    // Click KEV header → sort=kev (dir omitted since desc is its default)
    fireEvent.click(screen.getByTestId('sort-kev'));
    await waitFor(() => {
      const probe = screen.getByTestId('location-probe').textContent ?? '';
      expect(probe).toContain('sort=kev');
    });

    // Click KEV again → dir should flip (kev default is desc → flip to asc)
    fireEvent.click(screen.getByTestId('sort-kev'));
    await waitFor(() => {
      const probe = screen.getByTestId('location-probe').textContent ?? '';
      expect(probe).toContain('dir=asc');
    });
  });

  it('url_togglingKevOnly_reflectsKevOnlyParam', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith();
    await screen.findByText(/No devices ranked/i);

    // Toggle ON
    fireEvent.click(screen.getByTestId('kev-only-toggle'));
    await waitFor(() => {
      const probe = screen.getByTestId('location-probe').textContent ?? '';
      expect(probe).toContain('kevOnly=true');
    });

    // Toggle OFF — param deleted (omit-when-default)
    fireEvent.click(screen.getByTestId('kev-only-toggle'));
    await waitFor(() => {
      const probe = screen.getByTestId('location-probe').textContent ?? '';
      expect(probe).not.toContain('kevOnly');
    });
  });

  it('url_clearingFilters_deletesParams', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });

    renderWith('/threats?crit=HIGH&host=foo');
    await screen.findByText(/No devices ranked/i);

    // Reset criticality to 'all'
    fireEvent.change(screen.getByTestId('threats-crit-select'), { target: { value: 'all' } });

    // Clear host input
    fireEvent.change(screen.getByTestId('threats-host-filter'), { target: { value: '' } });

    await waitFor(() => {
      const probe = screen.getByTestId('location-probe').textContent ?? '';
      expect(probe).not.toContain('crit=');
      expect(probe).not.toContain('crit=');
      expect(probe).not.toContain('host=');
    });
  });

  // ---------------------------------------------------------------------------
  // feat/threats-cve-detail-drawer: CVE click opens full CveDetailPanel drawer
  // ---------------------------------------------------------------------------

  it('cveDetail_clickingCveRowOpensCveDetailPanel', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 99, hostname: 'host-99', ipAddress: '10.0.0.99', criticality: 'HIGH', score: '9.00', kevCount: 1 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([makeSummary('CVE-2024-9999', '8.5', true)]),
    );
    (api.cveDetail as ReturnType<typeof vi.fn>).mockResolvedValue({
      cveId: 'CVE-2024-9999',
      published: '2024-01-01T00:00:00Z',
      lastModified: '2024-01-02T00:00:00Z',
      vulnStatus: 'Analyzed',
      description: 'Test CVE detail description',
      cvssV31Score: '8.5',
      cvssV31Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cvssV30Score: null,
      cvssV30Vector: null,
      cvssV2Score: null,
      cvssV2Vector: null,
      fetchedAt: null,
      rawJson: null,
      kev: true,
      epssScore: '0.5',
      compositeScore: '8.5',
    });
    (api.listAffectedDevices as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    renderWith();
    const threatRow = await screen.findByTestId('threats-row-99');
    fireEvent.click(threatRow);

    // Wait for the CVE row to appear inside the related panel
    const cveRow = await screen.findByTestId('related-cves-row-CVE-2024-9999');

    // Click the CVE row → should open the CveDetailPanel drawer
    fireEvent.click(cveRow);

    const panel = await screen.findByTestId('cve-detail-panel');
    expect(panel).toBeInTheDocument();
    expect(panel).toHaveTextContent('CVE-2024-9999');
  });

  it('cveDetail_drawerFromThreats_rendersFullDetailParityWithCvesPage', async () => {
    // Asserts that opening a CVE from /threats renders the IDENTICAL full detail as
    // /cves: CVSS vector breakdown, references section, and affected-devices section
    // (including matched CPE and version range). Previously the test only checked that
    // the panel *opened* — this test ensures all sections render correctly.
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 100, hostname: 'host-100', ipAddress: '10.0.0.100', criticality: 'CRITICAL', score: '9.50', kevCount: 1 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([makeSummary('CVE-2024-FULL', '9.8', true)]),
    );
    (api.cveDetail as ReturnType<typeof vi.fn>).mockResolvedValue({
      cveId: 'CVE-2024-FULL',
      published: '2024-06-01T00:00:00Z',
      lastModified: '2024-06-02T00:00:00Z',
      vulnStatus: 'Analyzed',
      description: 'Full detail CVE description',
      cvssV31Score: '9.8',
      // Non-null vector → CvssVectorBreakdown must render Attack Vector etc.
      cvssV31Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cvssV30Score: null,
      cvssV30Vector: null,
      cvssV2Score: null,
      cvssV2Vector: null,
      fetchedAt: null,
      // rawJson with embedded references → References section renders parsed links
      rawJson: JSON.stringify({
        vulnerabilities: [{ cve: { references: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-FULL', source: 'NVD' }] } }],
      }),
      kev: true,
      epssScore: '0.75',
      compositeScore: '9.8',
    });
    // Affected device with matched CPE + range → affected-devices section renders evidence
    (api.listAffectedDevices as ReturnType<typeof vi.fn>).mockResolvedValue([
      {
        deviceId: 42,
        hostname: 'pg-server',
        ipAddress: '10.0.0.42',
        matchedPort: 5432,
        matchedService: 'postgresql',
        matchedVersion: '17.6.1.029',
        matchedCpe: 'cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*',
        matchedRangeStart: '17.0 (incl.)',
        matchedRangeEnd: '17.10 (excl.)',
      },
    ]);

    renderWith();
    const threatRow = await screen.findByTestId('threats-row-100');
    fireEvent.click(threatRow);
    const cveRow = await screen.findByTestId('related-cves-row-CVE-2024-FULL');
    fireEvent.click(cveRow);

    const panel = await screen.findByTestId('cve-detail-panel');
    expect(panel).toBeInTheDocument();

    // --- CVSS Vector breakdown section (CvssVectorBreakdown component) ---
    // The decoded metric grid must show "Attack Vector" when cvssV31Vector is present.
    await screen.findByText('Attack Vector');
    expect(screen.getByText('Attack Vector')).toBeInTheDocument();

    // --- References section ---
    // The parsed NVD link from rawJson must render as an anchor.
    const refLink = await screen.findByRole('link', { name: /nvd\.nist\.gov\/vuln\/detail\/CVE-2024-FULL/i });
    expect(refLink).toBeInTheDocument();

    // --- Affected Devices section with matched CPE + version range ---
    await screen.findByTestId('matched-cpe');
    expect(screen.getByTestId('matched-cpe')).toHaveTextContent('cpe:2.3:a:postgresql:postgresql');
    expect(screen.getByTestId('matched-range')).toHaveTextContent('17.0 (incl.)');
    expect(screen.getByTestId('matched-range')).toHaveTextContent('17.10 (excl.)');
    // The device link must be present
    expect(screen.getByRole('link', { name: /pg-server/i })).toBeInTheDocument();
  });

  it('cveDetail_closingDrawer_keepsThreatRowExpanded', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 88, hostname: 'host-88', ipAddress: '10.0.0.88', criticality: 'HIGH', score: '9.00', kevCount: 1 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([makeSummary('CVE-2024-0088', '7.5', false)]),
    );
    (api.cveDetail as ReturnType<typeof vi.fn>).mockResolvedValue({
      cveId: 'CVE-2024-0088',
      published: '2024-01-01T00:00:00Z',
      lastModified: '2024-01-02T00:00:00Z',
      vulnStatus: 'Analyzed',
      description: 'Detail for 0088',
      cvssV31Score: '7.5',
      cvssV31Vector: null,
      cvssV30Score: null,
      cvssV30Vector: null,
      cvssV2Score: null,
      cvssV2Vector: null,
      fetchedAt: null,
      rawJson: null,
      kev: false,
      epssScore: null,
      compositeScore: '7.5',
    });
    (api.listAffectedDevices as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    renderWith();
    const threatRow = await screen.findByTestId('threats-row-88');
    fireEvent.click(threatRow);

    const cveRow = await screen.findByTestId('related-cves-row-CVE-2024-0088');
    fireEvent.click(cveRow);

    const panel = await screen.findByTestId('cve-detail-panel');
    expect(panel).toBeInTheDocument();

    // Close the drawer
    fireEvent.click(screen.getByRole('button', { name: /close cve panel/i }));

    // CveDetailPanel should be gone
    await waitFor(() => expect(screen.queryByTestId('cve-detail-panel')).toBeNull());

    // But the related-CVEs panel for device 88 must still be visible
    expect(screen.getByTestId('threats-related-panel-88')).toBeInTheDocument();
    expect(screen.getByTestId('related-cves-row-CVE-2024-0088')).toBeInTheDocument();
  });

  // ---------------------------------------------------------------------------
  // feat/threats-open-device-detail: device detail inline in expanded row
  // ---------------------------------------------------------------------------

  const makeDevice = (id: number) => ({
    id,
    hostname: `host-${id}`,
    ipAddress: `10.0.0.${id}`,
    macAddress: null,
    criticality: 'HIGH' as const,
    osName: 'Linux',
    osAccuracy: 90,
    osCpe: null,
    firstSeen: '2024-01-01T00:00:00Z',
    lastSeen: '2024-01-02T00:00:00Z',
    lastSeenIface: null,
    serviceCount: 1,
    discoveryScope: 'HOME' as const,
    discoverySource: 'NMAP' as const,
  });

  const makeRisk = (deviceId: number) => ({
    deviceId,
    score: '7.50',
    topCveIds: [],
    components: { cvssMax: 7.5, epssMax: 0.1, kevPresent: false, criticalityWeight: 2 },
  });

  const makeServices = () => [
    { id: 1, deviceId: 1, port: 22, protocol: 'tcp', protocolFamily: 'INET' as const,
      name: 'ssh', product: 'OpenSSH', vendor: null, version: '8.0', observedAt: '2024-01-01T00:00:00Z' },
  ];

  it('deviceDetail_rowClick_rendersDeviceDetailPanelAlongsideRelatedCves', async () => {
    const deviceId = 55;
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId, hostname: 'host-55', ipAddress: '10.0.0.55', criticality: 'HIGH', score: '8.00', kevCount: 1 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(makePage([]));
    (api.getDevice as ReturnType<typeof vi.fn>).mockResolvedValue(makeDevice(deviceId));
    (api.deviceRisk as ReturnType<typeof vi.fn>).mockResolvedValue(makeRisk(deviceId));
    (api.listServicesForDevice as ReturnType<typeof vi.fn>).mockResolvedValue(makeServices());

    renderWith();
    const row = await screen.findByTestId(`threats-row-${deviceId}`);
    fireEvent.click(row);

    // RelatedCvesPanel still present
    await screen.findByTestId(`threats-related-panel-${deviceId}`);

    // DeviceDetailPanel now also visible
    await screen.findByTestId('device-detail-panel');
    expect(screen.getByTestId('device-detail-panel')).toBeInTheDocument();
  });

  it('deviceDetail_lazyFetch_onlyFetchesOnRowOpen', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 56, hostname: 'host-56', ipAddress: '10.0.0.56', criticality: 'HIGH', score: '8.00', kevCount: 0 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    (api.getDevice as ReturnType<typeof vi.fn>).mockResolvedValue(makeDevice(56));
    (api.deviceRisk as ReturnType<typeof vi.fn>).mockResolvedValue(makeRisk(56));
    (api.listServicesForDevice as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    renderWith();
    // Wait for table to appear — no row expanded yet
    await screen.findByTestId('threats-row-56');

    // Device fetch calls should NOT have been made before any row is clicked
    expect(api.getDevice).not.toHaveBeenCalled();
    expect(api.deviceRisk).not.toHaveBeenCalled();
    expect(api.listServicesForDevice).not.toHaveBeenCalled();

    // Now click the row
    fireEvent.click(screen.getByTestId('threats-row-56'));

    // After click the fetches should be triggered
    await waitFor(() => {
      expect(api.getDevice).toHaveBeenCalledWith(56);
      expect(api.deviceRisk).toHaveBeenCalledWith(56);
      expect(api.listServicesForDevice).toHaveBeenCalledWith(56);
    });
  });

  it('deviceDetail_closeDevicePanel_keepsRelatedCvesVisible', async () => {
    const deviceId = 57;
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId, hostname: 'host-57', ipAddress: '10.0.0.57', criticality: 'HIGH', score: '8.00', kevCount: 0 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(makePage([]));
    (api.getDevice as ReturnType<typeof vi.fn>).mockResolvedValue(makeDevice(deviceId));
    (api.deviceRisk as ReturnType<typeof vi.fn>).mockResolvedValue(makeRisk(deviceId));
    (api.listServicesForDevice as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    renderWith();
    fireEvent.click(await screen.findByTestId(`threats-row-${deviceId}`));

    // Both panels appear
    await screen.findByTestId(`threats-related-panel-${deviceId}`);
    await screen.findByTestId('device-detail-panel');

    // Close device-detail panel via its close button
    fireEvent.click(screen.getByRole('button', { name: /close panel/i }));

    // DeviceDetailPanel disappears
    await waitFor(() => expect(screen.queryByTestId('device-detail-panel')).toBeNull());

    // RelatedCvesPanel (and threat row) must still be visible
    expect(screen.getByTestId(`threats-related-panel-${deviceId}`)).toBeInTheDocument();
  });

  it('deviceDetail_switchingRows_swapsDeviceDetail', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 61, hostname: 'host-61', ipAddress: '10.0.0.61', criticality: 'HIGH', score: '9.00', kevCount: 0 },
      { deviceId: 62, hostname: 'host-62', ipAddress: '10.0.0.62', criticality: 'MEDIUM', score: '5.00', kevCount: 0 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(makePage([]));
    (api.getDevice as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce(makeDevice(61))
      .mockResolvedValueOnce(makeDevice(62));
    (api.deviceRisk as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce(makeRisk(61))
      .mockResolvedValueOnce(makeRisk(62));
    (api.listServicesForDevice as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    renderWith();
    fireEvent.click(await screen.findByTestId('threats-row-61'));
    await screen.findByTestId('device-detail-panel');

    // Switch to row 62
    fireEvent.click(screen.getByTestId('threats-row-62'));

    // Row 62's related panel appears, row 61's disappears
    await screen.findByTestId('threats-related-panel-62');
    expect(screen.queryByTestId('threats-related-panel-61')).toBeNull();

    // Only one device-detail panel (no stacking)
    await waitFor(() => {
      expect(screen.getAllByTestId('device-detail-panel')).toHaveLength(1);
    });
  });

  it('deviceDetail_adminRole_showsDecommissionControls', async () => {
    const deviceId = 70;
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId, hostname: 'host-70', ipAddress: '10.0.0.70', criticality: 'HIGH', score: '9.00', kevCount: 0 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(makePage([]));
    (api.getDevice as ReturnType<typeof vi.fn>).mockResolvedValue(makeDevice(deviceId));
    (api.deviceRisk as ReturnType<typeof vi.fn>).mockResolvedValue(makeRisk(deviceId));
    (api.listServicesForDevice as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    // Render with ADMIN role
    render(
      <MemoryRouter initialEntries={['/threats']}>
        <ThreatsDashboard isAdmin={true} />
      </MemoryRouter>,
    );

    fireEvent.click(await screen.findByTestId(`threats-row-${deviceId}`));
    await screen.findByTestId('device-detail-panel');

    // Decommission button only visible to admins
    expect(screen.getByRole('button', { name: /decommission/i })).toBeInTheDocument();
  });

  it('deviceDetail_viewerRole_noDecommissionControls', async () => {
    const deviceId = 71;
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId, hostname: 'host-71', ipAddress: '10.0.0.71', criticality: 'HIGH', score: '9.00', kevCount: 0 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(makePage([]));
    (api.getDevice as ReturnType<typeof vi.fn>).mockResolvedValue(makeDevice(deviceId));
    (api.deviceRisk as ReturnType<typeof vi.fn>).mockResolvedValue(makeRisk(deviceId));
    (api.listServicesForDevice as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    // Render with VIEWER role (default — isAdmin not passed)
    render(
      <MemoryRouter initialEntries={['/threats']}>
        <ThreatsDashboard />
      </MemoryRouter>,
    );

    fireEvent.click(await screen.findByTestId(`threats-row-${deviceId}`));
    await screen.findByTestId('device-detail-panel');

    // Decommission button must NOT be visible to viewers
    expect(screen.queryByRole('button', { name: /decommission/i })).toBeNull();
    // Inline-edit affordances must also be absent for viewers
    expect(screen.queryByRole('button', { name: /edit hostname/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /edit criticality/i })).toBeNull();
  });

  it('cveDetail_secondCveClick_swapsDrawerContent', async () => {
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId: 77, hostname: 'host-77', ipAddress: '10.0.0.77', criticality: 'CRITICAL', score: '9.50', kevCount: 2 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    (api.listFleetCves as ReturnType<typeof vi.fn>).mockResolvedValue(
      makePage([
        makeSummary('CVE-2024-AAA', '9.0', true),
        makeSummary('CVE-2024-BBB', '7.0', false),
      ]),
    );
    (api.cveDetail as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce({
        cveId: 'CVE-2024-AAA',
        published: '2024-01-01T00:00:00Z',
        lastModified: '2024-01-02T00:00:00Z',
        vulnStatus: 'Analyzed',
        description: 'Detail for AAA',
        cvssV31Score: '9.0',
        cvssV31Vector: null,
        cvssV30Score: null,
        cvssV30Vector: null,
        cvssV2Score: null,
        cvssV2Vector: null,
        fetchedAt: null,
        rawJson: null,
        kev: true,
        epssScore: null,
        compositeScore: '9.0',
      })
      .mockResolvedValueOnce({
        cveId: 'CVE-2024-BBB',
        published: '2024-01-01T00:00:00Z',
        lastModified: '2024-01-02T00:00:00Z',
        vulnStatus: 'Analyzed',
        description: 'Detail for BBB',
        cvssV31Score: '7.0',
        cvssV31Vector: null,
        cvssV30Score: null,
        cvssV30Vector: null,
        cvssV2Score: null,
        cvssV2Vector: null,
        fetchedAt: null,
        rawJson: null,
        kev: false,
        epssScore: null,
        compositeScore: '7.0',
      });
    (api.listAffectedDevices as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    renderWith();
    const threatRow = await screen.findByTestId('threats-row-77');
    fireEvent.click(threatRow);

    // Click first CVE
    const cveRowA = await screen.findByTestId('related-cves-row-CVE-2024-AAA');
    fireEvent.click(cveRowA);

    const panel = await screen.findByTestId('cve-detail-panel');
    expect(panel).toHaveTextContent('CVE-2024-AAA');

    // Click second CVE — drawer should swap to BBB without doubling
    const cveRowB = await screen.findByTestId('related-cves-row-CVE-2024-BBB');
    fireEvent.click(cveRowB);

    await waitFor(() => expect(screen.getByTestId('cve-detail-panel')).toHaveTextContent('CVE-2024-BBB'));
    // Only one panel should exist
    expect(screen.getAllByTestId('cve-detail-panel')).toHaveLength(1);
  });

  // ---------------------------------------------------------------------------
  // N4 — device-detail fetch failure surfaces inline error notice
  // ---------------------------------------------------------------------------

  it('deviceDetail_fetchFailure_rendersInlineErrorNotice', async () => {
    const deviceId = 80;
    (api.topRisk as ReturnType<typeof vi.fn>).mockResolvedValue([
      { deviceId, hostname: 'host-80', ipAddress: '10.0.0.80', criticality: 'HIGH', score: '8.00', kevCount: 0 },
    ]);
    (api.feedsStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      epss: { scoreDate: '2026-05-24', rowCount: 100 },
      kev: { lastIngestedAt: '2026-05-24T00:00:00Z', entryCount: 50 },
      nvd: { lastModified: '2026-05-24T00:00:00Z', rowCount: 42 },
    });
    // All three detail fetches reject
    (api.getDevice as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('network error'));
    (api.deviceRisk as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('network error'));
    (api.listServicesForDevice as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('network error'));

    renderWith();
    fireEvent.click(await screen.findByTestId(`threats-row-${deviceId}`));

    // Error notice visible inside the expanded row, DeviceDetailPanel absent
    const notice = await screen.findByTestId('device-detail-error');
    expect(notice).toBeInTheDocument();
    expect(notice).toHaveTextContent(/Could not load device detail/i);
    expect(screen.queryByTestId('device-detail-panel')).toBeNull();
  });
});

