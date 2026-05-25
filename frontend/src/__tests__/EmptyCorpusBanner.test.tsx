import { render, screen, fireEvent, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../api/client', () => ({
  api: {
    feedsStatus: vi.fn(),
    triggerInitialSync: vi.fn(),
  },
}));

import { EmptyCorpusBanner } from '../components/EmptyCorpusBanner';
import { api } from '../api/client';

const mockApi = api as unknown as {
  feedsStatus: ReturnType<typeof vi.fn>;
  triggerInitialSync: ReturnType<typeof vi.fn>;
};

const EMPTY_STATUS = {
  epss: { scoreDate: null, rowCount: 0 },
  kev: { lastIngestedAt: null, entryCount: 0 },
  nvd: { lastModified: null, rowCount: 0 },
};

const FULL_STATUS = {
  epss: { scoreDate: '2025-01-01', rowCount: 1000 },
  kev: { lastIngestedAt: '2025-01-01T00:00:00Z', entryCount: 100 },
  nvd: { lastModified: '2025-01-01T00:00:00Z', rowCount: 200000 },
};

describe('<EmptyCorpusBanner />', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockApi.feedsStatus.mockResolvedValue(EMPTY_STATUS);
    mockApi.triggerInitialSync.mockResolvedValue({ status: 'started', startedAt: '2026-01-01T00:00:00Z' });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it('(a) renders nothing when all rowCounts are non-zero', async () => {
    mockApi.feedsStatus.mockResolvedValue(FULL_STATUS);
    const { container } = render(<EmptyCorpusBanner isAdmin={true} />);
    await act(async () => { await Promise.resolve(); });
    expect(container.firstChild).toBeNull();
  });

  it('(b) shows banner and button when any rowCount is 0 and isAdmin=true', async () => {
    render(<EmptyCorpusBanner isAdmin={true} />);
    await act(async () => { await Promise.resolve(); });

    expect(screen.getByText(/Threat intelligence feeds are empty/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Sync NVD/i })).toBeInTheDocument();
  });

  it('(c) shows banner but NO button when isAdmin=false', async () => {
    render(<EmptyCorpusBanner isAdmin={false} />);
    await act(async () => { await Promise.resolve(); });

    expect(screen.getByText(/Threat intelligence feeds are empty/i)).toBeInTheDocument();
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('(d) button click invokes triggerInitialSync exactly once and shows Syncing…', async () => {
    mockApi.triggerInitialSync.mockImplementation(
      () => new Promise(resolve => setTimeout(() => resolve({ status: 'started', startedAt: '' }), 5000))
    );

    render(<EmptyCorpusBanner isAdmin={true} />);
    await act(async () => { await Promise.resolve(); });

    const btn = screen.getByRole('button', { name: /Sync NVD/i });
    await act(async () => { fireEvent.click(btn); });

    expect(mockApi.triggerInitialSync).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: /Syncing/i })).toBeDisabled();
  });

  it('(e) after 10s polling tick feedsStatus is called a second time', async () => {
    render(<EmptyCorpusBanner isAdmin={true} />);
    await act(async () => { await Promise.resolve(); });

    expect(mockApi.feedsStatus).toHaveBeenCalledTimes(1);

    await act(async () => {
      vi.advanceTimersByTime(10_000);
      await Promise.resolve();
    });

    expect(mockApi.feedsStatus).toHaveBeenCalledTimes(2);
  });

  it('(f) banner unmounts when polling returns all rowCounts > 0', async () => {
    mockApi.feedsStatus
      .mockResolvedValueOnce(EMPTY_STATUS)
      .mockResolvedValueOnce(FULL_STATUS);

    const { container } = render(<EmptyCorpusBanner isAdmin={true} />);
    await act(async () => { await Promise.resolve(); });

    expect(screen.getByText(/Threat intelligence feeds are empty/i)).toBeInTheDocument();

    await act(async () => {
      vi.advanceTimersByTime(10_000);
      await Promise.resolve();
    });

    expect(container.firstChild).toBeNull();
  });
});
