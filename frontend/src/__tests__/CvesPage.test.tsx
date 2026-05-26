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
    expect(listFleetCves).toHaveBeenCalledWith(0, 25, undefined, undefined);
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

    expect(listFleetCves).toHaveBeenLastCalledWith(0, 25, 7.0, undefined);
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

    expect(listFleetCves).toHaveBeenLastCalledWith(1, 25, undefined, undefined);
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
      expect(listFleetCves).toHaveBeenCalledWith(0, 25, undefined, 42);
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
      expect(listFleetCves).toHaveBeenCalledWith(0, 25, undefined, 42);
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
});
