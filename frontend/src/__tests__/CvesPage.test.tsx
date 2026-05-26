import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CvesPage } from '../pages/CvesPage';
import { api } from '../api/client';
import type { CveSummaryDto, Page } from '../api/types';

vi.mock('../api/client', () => ({
  api: {
    listFleetCves: vi.fn(),
  },
}));

const listFleetCves = vi.mocked(api.listFleetCves);

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

describe('<CvesPage />', () => {
  beforeEach(() => {
    listFleetCves.mockReset();
  });

  it('renders the default fleet CVE table on mount', async () => {
    listFleetCves.mockResolvedValueOnce(defaultPage);

    render(<CvesPage />);

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });
    expect(screen.getByText('CVE-2024-99999')).toBeInTheDocument();
    expect(listFleetCves).toHaveBeenCalledWith(0, 25, undefined);
  });

  it('re-fetches with minScore=7.0 when severity is set to High', async () => {
    listFleetCves
      .mockResolvedValueOnce(defaultPage)
      .mockResolvedValueOnce(highSeverityPage);

    render(<CvesPage />);

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'high' } });

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-11111')).toBeInTheDocument();
    });

    expect(listFleetCves).toHaveBeenLastCalledWith(0, 25, 7.0);
    expect(listFleetCves).toHaveBeenCalledTimes(2);
  });

  it('advances to the next page when Next is clicked', async () => {
    listFleetCves
      .mockResolvedValueOnce(pageOneOfTwo)
      .mockResolvedValueOnce(pageTwoOfTwo);

    render(<CvesPage />);

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-12345')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Next' }));

    await waitFor(() => {
      expect(screen.getByText('CVE-2024-22222')).toBeInTheDocument();
    });

    expect(listFleetCves).toHaveBeenLastCalledWith(1, 25, undefined);
  });

  it('shows the error banner when listFleetCves rejects', async () => {
    listFleetCves.mockRejectedValueOnce(new Error('boom'));

    render(<CvesPage />);

    expect(await screen.findByText(/boom/)).toBeInTheDocument();
  });

  it('renders the empty placeholder when the API returns no rows', async () => {
    listFleetCves.mockResolvedValueOnce(emptyPage);

    render(<CvesPage />);

    await waitFor(() => {
      expect(screen.getByText('No CVEs match this filter.')).toBeInTheDocument();
    });
  });
});
