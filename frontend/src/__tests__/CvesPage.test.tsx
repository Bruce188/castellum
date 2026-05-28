import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom';
import { CvesPage } from '../pages/CvesPage';
import { api } from '../api/client';
import type { CveSummaryDto, Device, Page } from '../api/types';

vi.mock('../api/client', () => ({
  api: {
    listFleetCves: vi.fn(),
    getDevice: vi.fn(),
    cveDetail: vi.fn(),
    listAffectedDevices: vi.fn(),
  },
}));

const listFleetCves = vi.mocked(api.listFleetCves);
const getDevice = vi.mocked(api.getDevice);
const cveDetail = vi.mocked(api.cveDetail);
const listAffectedDevices = vi.mocked(api.listAffectedDevices);

const baseCve: CveSummaryDto = {
  cveId: 'CVE-2024-12345',
  published: null,
  lastModified: '2024-01-15T00:00:00Z',
  vulnStatus: null,
  description: 'Example vulnerability',
  cvssV31Score: '8.1',
  cvssV31Vector: null,
  cvssV30Score: null,
  cvssV30Vector: null,
  cvssV2Score: null,
  cvssV2Vector: null,
  fetchedAt: null,
  // v3-F1 enrichment fields — default to no-signal so existing tests remain stable.
  kev: false,
  epssScore: null,
  compositeScore: null,
};

const defaultPage: Page<CveSummaryDto> = {
  content: [
    baseCve,
    { ...baseCve, cveId: 'CVE-2024-99999', cvssV31Score: '5.5', description: 'Second row' },
  ],
  totalElements: 2,
  totalPages: 1,
  number: 0,
  size: 25,
};

const highSeverityPage: Page<CveSummaryDto> = {
  content: [{ ...baseCve, cveId: 'CVE-2024-11111', cvssV31Score: '9.2', description: 'High sev row' }],
  totalElements: 1,
  totalPages: 1,
  number: 0,
  size: 25,
};

const emptyPage: Page<CveSummaryDto> = {
  content: [],
  totalElements: 0,
  totalPages: 0,
  number: 0,
  size: 25,
};

const pageOneOfTwo: Page<CveSummaryDto> = {
  content: [baseCve],
  totalElements: 26,
  totalPages: 2,
  number: 0,
  size: 25,
};

const pageTwoOfTwo: Page<CveSummaryDto> = {
  content: [{ ...baseCve, cveId: 'CVE-2024-22222', cvssV31Score: '6.0', description: 'Page two row' }],
  totalElements: 26,
  totalPages: 2,
  number: 1,
  size: 25,
};

const sampleDevice: Device = {
  id: 42,
  ipAddress: '10.0.0.42',
  hostname: 'host-42',
  macAddress: null,
  firstSeen: '2024-01-01T00:00:00Z',
  lastSeen: '2024-01-02T00:00:00Z',
  criticality: 'MEDIUM',
  discoveryScope: 'HOME',
  lastSeenIface: null,
  discoverySource: null,
  serviceCount: 0,
  osName: null,
  osAccuracy: null,
  osCpe: null,
};

function renderWith(initialPath = '/cves') {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Routes>
        <Route path="/cves" element={<CvesPage />} />
      </Routes>
    </MemoryRouter>
  );
}

// Surfaces the live router location.search so a test can assert URL param
// writes (e.g. that a sort-header click is observable in the URL, mirroring the
// Playwright e2e). Rendered as a sibling of <Routes> so it always mounts and
// re-renders on navigation.
function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="location-search">{loc.search}</div>;
}

function renderWithLocationProbe(initialPath = '/cves') {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <LocationProbe />
      <Routes>
        <Route path="/cves" element={<CvesPage />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('<CvesPage />', () => {
  beforeEach(() => {
    listFleetCves.mockReset();
    getDevice.mockReset();
  });

  it('renders the default fleet CVE table on mount', async () => {
    listFleetCves.mockResolvedValueOnce(defaultPage);

    renderWith();

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });
    expect(screen.getByText('CVE-2024-99999')).toBeInTheDocument();
    expect(listFleetCves).toHaveBeenCalledWith(0, 25, undefined, undefined, undefined, 'composite');
  });

  it('re-fetches with minScore=7.0 when severity is set to High', async () => {
    listFleetCves
      .mockResolvedValueOnce(defaultPage)
      .mockResolvedValueOnce(highSeverityPage);

    renderWith();

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'high' } });

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-11111')).toBeInTheDocument();
    });

    expect(listFleetCves).toHaveBeenLastCalledWith(0, 25, 7.0, undefined, undefined, 'composite');
    expect(listFleetCves).toHaveBeenCalledTimes(2);
  });

  it('advances to the next page when Next is clicked', async () => {
    listFleetCves
      .mockResolvedValueOnce(pageOneOfTwo)
      .mockResolvedValueOnce(pageTwoOfTwo);

    renderWith();

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Next' }));

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-22222')).toBeInTheDocument();
    });

    expect(listFleetCves).toHaveBeenLastCalledWith(1, 25, undefined, undefined, undefined, 'composite');
  });

  it('shows the error banner when listFleetCves rejects', async () => {
    listFleetCves.mockRejectedValueOnce(new Error('boom'));

    renderWith();

    expect(await screen.findByText(/boom/)).toBeInTheDocument();
  });

  it('renders the empty placeholder when the API returns no rows', async () => {
    listFleetCves.mockResolvedValueOnce(emptyPage);

    renderWith();

    await waitFor(() => {
      expect(screen.getByText('No CVEs match this filter.')).toBeInTheDocument();
    });
  });

  it('passes deviceId from search params to api.listFleetCves', async () => {
    listFleetCves.mockResolvedValueOnce(defaultPage);
    getDevice.mockResolvedValueOnce(sampleDevice);

    renderWith('/cves?deviceId=42');

    await waitFor(() => {
      expect(listFleetCves).toHaveBeenCalledWith(0, 25, undefined, 42, undefined, 'composite');
    });
  });

  it('renders chip with fetched device hostname and ip', async () => {
    listFleetCves.mockResolvedValueOnce(defaultPage);
    getDevice.mockResolvedValueOnce(sampleDevice);

    renderWith('/cves?deviceId=42');

    expect(await screen.findByText(/host-42 \(10\.0\.0\.42\)/)).toBeInTheDocument();
  });

  it('chip falls back to bare device id when getDevice rejects', async () => {
    listFleetCves.mockResolvedValueOnce(defaultPage);
    getDevice.mockRejectedValueOnce(new Error('404'));

    renderWith('/cves?deviceId=42');

    expect(await screen.findByText(/device #42/)).toBeInTheDocument();
  });

  it('dismissing chip clears filter and refetches', async () => {
    listFleetCves
      .mockResolvedValueOnce(defaultPage)
      .mockResolvedValueOnce(defaultPage);
    getDevice.mockResolvedValueOnce(sampleDevice);

    renderWith('/cves?deviceId=42');

    await waitFor(() => {
      expect(listFleetCves).toHaveBeenCalledWith(0, 25, undefined, 42, undefined, 'composite');
    });

    fireEvent.click(screen.getByTestId('cves-chip-dismiss'));

    await waitFor(() => {
      const calls = listFleetCves.mock.calls;
      expect(calls[calls.length - 1][3]).toBeUndefined();
    });
  });

  it('CvesPage_renders_select_none_on_tr_and_select_text_on_id_and_description', async () => {
    listFleetCves.mockResolvedValueOnce(defaultPage);

    renderWith();

    const idCell = await screen.findByText('CVE-2024-12345');
    const row = idCell.closest('tr');
    expect(row).not.toBeNull();
    expect(row!.className).toContain('select-none');
    expect(idCell.className).toContain('select-text');

    const descCell = screen.getByText('Example vulnerability');
    expect(descCell.className).toContain('select-text');
  });

  // ────────────────────────────────────────────────────────────────────────
  // v3-F1 — new visible columns (KEV / EPSS / Composite), KEV-only toggle,
  // sort-header clicks, URL-bound state.
  // ────────────────────────────────────────────────────────────────────────

  it('cvesPage_rendersThreeNewColumns_KEV_EPSS_Composite', async () => {
    listFleetCves.mockResolvedValueOnce({
      content: [baseCve],
      totalElements: 1,
      totalPages: 1,
      number: 0,
      size: 25,
    });

    renderWith();

    // Wait for the row to render so the headers are definitely in the DOM.
    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    expect(screen.getByRole('columnheader', { name: /KEV/i })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: /EPSS/i })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: /Composite/i })).toBeInTheDocument();
  });

  it('cvesPage_rendersRedKevBadge_whenKevTrue', async () => {
    listFleetCves.mockResolvedValueOnce({
      content: [{ ...baseCve, kev: true }],
      totalElements: 1,
      totalPages: 1,
      number: 0,
      size: 25,
    });

    renderWith();

    const badge = await screen.findByTestId('kev-badge');
    expect(badge).toBeInTheDocument();
    expect(badge.className).toMatch(/red|bg-red/i);
  });

  it('cvesPage_rendersEpssAsPercentWithTwoDecimals', async () => {
    listFleetCves.mockResolvedValueOnce({
      content: [{ ...baseCve, epssScore: '0.0532' }],
      totalElements: 1,
      totalPages: 1,
      number: 0,
      size: 25,
    });

    renderWith();

    // Decision 7 — raw probability × 100, 2 decimals.
    expect(await screen.findByText('5.32%')).toBeInTheDocument();
  });

  it('cvesPage_compositeCellColorMatchesSeverityRamp', async () => {
    listFleetCves.mockResolvedValueOnce({
      content: [{ ...baseCve, compositeScore: '8.5' }],
      totalElements: 1,
      totalPages: 1,
      number: 0,
      size: 25,
    });

    renderWith();

    const compositeText = await screen.findByText('8.50');
    // 8.5 falls in the "high" band (>= 7.0) — severityClass returns orange-600/font-medium
    // for high. The cell wrapping <td> carries the class via severityClassFromString.
    const compositeCell = compositeText.closest('td');
    expect(compositeCell).not.toBeNull();
    expect(compositeCell!.className).toMatch(/text-(orange|red)-/);
  });

  it('cvesPage_clickingCompositeHeaderTogglesSortAndRefetches', async () => {
    listFleetCves
      .mockResolvedValueOnce(defaultPage) // initial render
      .mockResolvedValueOnce(defaultPage); // refetch after sort click

    renderWith();

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Composite/i }));

    await waitFor(() => {
      const lastCall = listFleetCves.mock.calls[listFleetCves.mock.calls.length - 1];
      // listFleetCves signature: (page, size, minScore, deviceId, kevOnly, sort)
      expect(lastCall[5]).toBe('composite');
    });
  });

  it('cvesPage_clickingCompositeHeader_writesSortParamToUrl', async () => {
    // Regression guard: composite is the default sort, so a prior
    // "delete the param when the clicked key is already active" branch left the
    // URL paramless after clicking the (default-active) Composite header — green
    // at the unit level (the refetch still rode the default) but red in the
    // Playwright e2e, which asserts the URL. A header click must ALWAYS write an
    // explicit ?sort=<key> so the active ordering is deep-linkable and
    // observable. Mirrors tests/cve.spec.ts "clicking the Composite header sorts
    // by composite".
    listFleetCves.mockResolvedValue(defaultPage);

    renderWithLocationProbe('/cves');

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    // A fresh /cves load rides the composite default without writing ?sort=.
    expect(screen.getByTestId('location-search').textContent).not.toContain('sort=');

    fireEvent.click(screen.getByRole('button', { name: /Composite/i }));

    await waitFor(() => {
      expect(screen.getByTestId('location-search').textContent).toContain('sort=composite');
    });
  });

  it('cvesPage_kevOnlyTogglesUrlParamAndFiltersList', async () => {
    listFleetCves
      .mockResolvedValueOnce(defaultPage) // initial render
      .mockResolvedValueOnce(defaultPage); // refetch after toggle

    renderWith();

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('kev-only-toggle'));

    await waitFor(() => {
      const lastCall = listFleetCves.mock.calls[listFleetCves.mock.calls.length - 1];
      // Position 4 is kevOnly. The page passes `kevOnly || undefined` so we expect true.
      expect(lastCall[4]).toBe(true);
    });
  });

  it('cvesPage_rendersEmDash_whenEpssAbsent', async () => {
    listFleetCves.mockResolvedValueOnce({
      content: [{ ...baseCve, epssScore: undefined as any }],
      totalElements: 1,
      totalPages: 1,
      number: 0,
      size: 25,
    });

    renderWith();

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    // The EPSS cell must render an em-dash and must NOT contain NaN or NaN%.
    const allDashes = screen.getAllByText('—');
    expect(allDashes.length).toBeGreaterThan(0);
    expect(screen.queryByText(/NaN/)).toBeNull();
  });

  it('cvesPage_rendersEmDash_whenCompositeAbsent', async () => {
    listFleetCves.mockResolvedValueOnce({
      content: [{ ...baseCve, compositeScore: undefined as any }],
      totalElements: 1,
      totalPages: 1,
      number: 0,
      size: 25,
    });

    renderWith();

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    // The Composite cell must render an em-dash and must NOT contain NaN.
    const allDashes = screen.getAllByText('—');
    expect(allDashes.length).toBeGreaterThan(0);
    expect(screen.queryByText(/NaN/)).toBeNull();
  });

  // ────────────────────────────────────────────────────────────────────────
  // Task 1.1 — CVSS column sort toggle (RED)
  // ────────────────────────────────────────────────────────────────────────

  it('cvesPage_clickingCvssHeaderTogglesSortToCvss', async () => {
    listFleetCves
      .mockResolvedValueOnce(defaultPage)
      .mockResolvedValueOnce(defaultPage);

    renderWith('/cves');

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /CVSS/i }));

    await waitFor(() => {
      expect(listFleetCves.mock.calls.at(-1)![5]).toBe('cvss');
    });
  });

  it('cvesPage_cvssHeader_isInteractiveButton', async () => {
    listFleetCves.mockResolvedValueOnce(defaultPage);

    renderWith('/cves');

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    expect(screen.getByRole('columnheader', { name: /CVSS/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /CVSS/i })).toBeInTheDocument();
  });

  it('cvesPage_activeCvssSort_showsDirectionIndicator', async () => {
    listFleetCves.mockResolvedValueOnce(defaultPage);

    renderWith('/cves?sort=cvss');

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    const cvssBtn = screen.getByRole('button', { name: /CVSS/i });
    expect(cvssBtn.textContent).toMatch(/↓/);

    // Use the columnheader to scope the KEV sort button (avoids matching the "KEV only" toggle)
    const kevHeader = screen.getByRole('columnheader', { name: /KEV/i });
    const kevSortBtn = kevHeader.querySelector('button')!;
    expect(kevSortBtn.textContent).not.toMatch(/↓/);
  });

  // ────────────────────────────────────────────────────────────────────────
  // Task 2.1 — Composite default + client-side stable tiebreak (RED)
  // ────────────────────────────────────────────────────────────────────────

  it('cvesPage_defaultRender_requestsCompositeSort', async () => {
    listFleetCves.mockResolvedValueOnce(defaultPage);

    renderWith('/cves');

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    expect(listFleetCves).toHaveBeenCalledWith(0, 25, undefined, undefined, undefined, 'composite');
  });

  it('cvesPage_compositeDefault_ordersKevHigherEpssAboveTiedCvssNonKev', async () => {
    const rowA = {
      ...baseCve,
      cveId: 'CVE-2023-44487',
      cvssV31Score: '10.0',
      kev: true,
      epssScore: '0.9445',
      compositeScore: '10.00',
    };
    const rowB = {
      ...baseCve,
      cveId: 'CVE-2018-1058',
      cvssV31Score: '10.0',
      kev: false,
      epssScore: '0.8201',
      compositeScore: '10.00',
    };

    // Server returns B-then-A (alphabetical = the bug)
    listFleetCves.mockResolvedValueOnce({
      content: [rowB, rowA],
      totalElements: 2,
      totalPages: 1,
      number: 0,
      size: 25,
    });

    renderWith('/cves');

    await waitFor(() => {
      expect(screen.getByText('CVE-2023-44487')).toBeInTheDocument();
      expect(screen.getByText('CVE-2018-1058')).toBeInTheDocument();
    });

    const cells = screen.getAllByText(/^CVE-20(23|18)-/);
    expect(cells[0].textContent).toBe('CVE-2023-44487');
    expect(cells[1].textContent).toBe('CVE-2018-1058');
  });

  it('cvesPage_explicitCvssSortParam_winsOverCompositeDefault', async () => {
    listFleetCves.mockResolvedValueOnce(defaultPage);

    renderWith('/cves?sort=cvss');

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    expect(listFleetCves.mock.calls.at(-1)![5]).toBe('cvss');
  });

  // ────────────────────────────────────────────────────────────────────────
  // Task 3.1 — CVE-id client-side search (RED)
  // ────────────────────────────────────────────────────────────────────────

  it('cvesPage_typingCveIdSubstring_narrowsRenderedRows', async () => {
    listFleetCves.mockResolvedValue(defaultPage);

    renderWith('/cves');

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
      expect(screen.getByText('CVE-2024-99999')).toBeInTheDocument();
    });

    const input = screen.getByTestId('cves-search-input');
    fireEvent.change(input, { target: { value: '99999' } });

    await waitFor(() => {
      expect(screen.queryByText('CVE-2024-12345')).toBeNull();
      expect(screen.getByText('CVE-2024-99999')).toBeInTheDocument();
    });
  });

  it('cvesPage_clearingSearch_restoresFullList', async () => {
    listFleetCves.mockResolvedValue(defaultPage);

    renderWith('/cves');

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    const input = screen.getByTestId('cves-search-input');
    fireEvent.change(input, { target: { value: '99999' } });

    await waitFor(() => {
      expect(screen.queryByText('CVE-2024-12345')).toBeNull();
    });

    fireEvent.change(input, { target: { value: '' } });

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
      expect(screen.getByText('CVE-2024-99999')).toBeInTheDocument();
    });
  });

  it('cvesPage_search_roundTripsThroughSearchParams', async () => {
    listFleetCves.mockResolvedValue(defaultPage);

    renderWith('/cves?q=99999');

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-99999')).toBeInTheDocument();
    });

    const input = screen.getByTestId('cves-search-input');
    expect((input as HTMLInputElement).value).toBe('99999');
    expect(screen.queryByText('CVE-2024-12345')).toBeNull();
  });

  it('cvesPage_searchFiltersClientSide_doesNotRefetch', async () => {
    listFleetCves.mockResolvedValue(defaultPage);

    renderWith('/cves');

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    const callsBefore = listFleetCves.mock.calls.length;

    const input = screen.getByTestId('cves-search-input');
    fireEvent.change(input, { target: { value: '99999' } });

    await waitFor(() => {
      expect(screen.queryByText('CVE-2024-12345')).toBeNull();
    });

    expect(listFleetCves.mock.calls.length).toBe(callsBefore);
  });

  // ────────────────────────────────────────────────────────────────────────
  // Task 4.1 — Discoverability pass (RED)
  // ────────────────────────────────────────────────────────────────────────

  it('cvesPage_searchInput_isQueryableByLabelAndTestid', async () => {
    listFleetCves.mockResolvedValueOnce(defaultPage);

    renderWith('/cves');

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    expect(screen.getByTestId('cves-search-input')).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/search cve id/i)).toBeInTheDocument();
  });

  it('cvesPage_sortableHeaders_exposeAriaSort', async () => {
    listFleetCves.mockResolvedValueOnce(defaultPage);

    renderWith('/cves?sort=cvss');

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    const cvssHeader = screen.getByRole('columnheader', { name: /CVSS/i });
    expect(cvssHeader.getAttribute('aria-sort')).toBe('descending');

    const compositeHeader = screen.getByRole('columnheader', { name: /Composite/i });
    expect(compositeHeader.getAttribute('aria-sort')).toBe('none');
  });

  it('cvesPage_idleSortHeaders_showNeutralGlyph', async () => {
    listFleetCves.mockResolvedValueOnce(defaultPage);

    // Default = composite active
    renderWith('/cves');

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    // Scope KEV sort button via columnheader to avoid matching the "KEV only" toggle
    const kevHeader = screen.getByRole('columnheader', { name: /KEV/i });
    const kevSortBtn = kevHeader.querySelector('button')!;
    expect(kevSortBtn.textContent).toContain('↕');

    const compositeBtn = screen.getByRole('button', { name: /Composite/i });
    expect(compositeBtn.textContent).toContain('↓');
  });

  // ────────────────────────────────────────────────────────────────────────
  // F8 — CVE row interaction (open detail drawer)
  // ────────────────────────────────────────────────────────────────────────

  describe('CVE row interaction', () => {
    beforeEach(() => {
      listFleetCves.mockResolvedValue(defaultPage);
      cveDetail.mockResolvedValue({
        cveId: 'CVE-2024-12345',
        published: null,
        lastModified: '2024-01-15T00:00:00Z',
        vulnStatus: null,
        description: 'Drawer description text.',
        cvssV31Score: '8.1',
        cvssV31Vector: null,
        cvssV30Score: null,
        cvssV30Vector: null,
        cvssV2Score: null,
        cvssV2Vector: null,
        fetchedAt: null,
        rawJson: null,
        kev: false,
        epssScore: null,
        compositeScore: null,
      });
      listAffectedDevices.mockResolvedValue([]);
    });

    it('clicking a CVE row opens the detail drawer and calls cveDetail exactly once', async () => {
      render(
        <MemoryRouter initialEntries={['/cves']}>
          <Routes><Route path="/cves" element={<CvesPage />} /></Routes>
        </MemoryRouter>
      );
      await waitFor(() => expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument());

      fireEvent.click(screen.getByText('CVE-2024-12345'));

      await waitFor(() =>
        expect(screen.getByTestId('cve-detail-panel')).toBeInTheDocument()
      );
      expect(cveDetail).toHaveBeenCalledTimes(1);
      expect(cveDetail).toHaveBeenCalledWith('CVE-2024-12345');
    });

    it('affected-nodes list renders from mocked reverse response', async () => {
      listAffectedDevices.mockResolvedValue([
        { deviceId: 42, hostname: 'host-1', ipAddress: '10.0.0.42',
          matchedPort: 22, matchedService: 'openssh', matchedVersion: '8.2' },
      ]);
      render(
        <MemoryRouter initialEntries={['/cves']}>
          <Routes><Route path="/cves" element={<CvesPage />} /></Routes>
        </MemoryRouter>
      );
      await waitFor(() => expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument());
      fireEvent.click(screen.getByText('CVE-2024-12345'));
      await waitFor(() => expect(screen.getByText('host-1')).toBeInTheDocument());
    });

    it('zero-affected empty state renders in the drawer', async () => {
      listAffectedDevices.mockResolvedValue([]);
      render(
        <MemoryRouter initialEntries={['/cves']}>
          <Routes><Route path="/cves" element={<CvesPage />} /></Routes>
        </MemoryRouter>
      );
      await waitFor(() => expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument());
      fireEvent.click(screen.getByText('CVE-2024-12345'));
      await waitFor(() =>
        expect(screen.getByText(/no affected devices/i)).toBeInTheDocument()
      );
    });

    it('Enter key on a CVE row opens the detail drawer and calls cveDetail', async () => {
      render(
        <MemoryRouter initialEntries={['/cves']}>
          <Routes><Route path="/cves" element={<CvesPage />} /></Routes>
        </MemoryRouter>
      );
      await waitFor(() => expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument());

      // Find the <tr> row that contains the CVE id cell.
      const cveIdCell = screen.getByText('CVE-2024-12345');
      const row = cveIdCell.closest('tr');
      expect(row).not.toBeNull();

      fireEvent.keyDown(row!, { key: 'Enter' });

      await waitFor(() =>
        expect(screen.getByTestId('cve-detail-panel')).toBeInTheDocument()
      );
      expect(cveDetail).toHaveBeenCalledWith('CVE-2024-12345');
    });
  });
});
