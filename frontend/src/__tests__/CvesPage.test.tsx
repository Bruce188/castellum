import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { CvesPage } from '../pages/CvesPage';
import { api } from '../api/client';
import type { CveSummaryDto, Device, Page } from '../api/types';

vi.mock('../api/client', () => ({
  api: {
    listFleetCves: vi.fn(),
    getDevice: vi.fn(),
  },
}));

const listFleetCves = vi.mocked(api.listFleetCves);
const getDevice = vi.mocked(api.getDevice);

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
    expect(listFleetCves).toHaveBeenCalledWith(0, 25, undefined, undefined, undefined, undefined);
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

    expect(listFleetCves).toHaveBeenLastCalledWith(0, 25, 7.0, undefined, undefined, undefined);
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

    expect(listFleetCves).toHaveBeenLastCalledWith(1, 25, undefined, undefined, undefined, undefined);
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
      expect(listFleetCves).toHaveBeenCalledWith(0, 25, undefined, 42, undefined, undefined);
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
      expect(listFleetCves).toHaveBeenCalledWith(0, 25, undefined, 42, undefined, undefined);
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
});
