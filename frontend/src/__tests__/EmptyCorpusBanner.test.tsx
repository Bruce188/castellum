import { render, screen, fireEvent, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../api/client', () => ({
  api: {
    feedsStatus: vi.fn(),
    triggerInitialSync: vi.fn(),
    syncStatus: vi.fn(),
  },
}));

import { EmptyCorpusBanner } from '../components/EmptyCorpusBanner';
import { api } from '../api/client';

const mockApi = api as unknown as {
  feedsStatus: ReturnType<typeof vi.fn>;
  triggerInitialSync: ReturnType<typeof vi.fn>;
  syncStatus: ReturnType<typeof vi.fn>;
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
    localStorage.clear();
    mockApi.feedsStatus.mockResolvedValue(EMPTY_STATUS);
    mockApi.triggerInitialSync.mockResolvedValue({ status: 'started', startedAt: '2026-01-01T00:00:00Z' });
    mockApi.syncStatus.mockResolvedValue({ running: false, startedAt: null });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
    localStorage.clear();
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

  it('(g) interval is cleared once feeds populate — no further fetches after isEmpty=false transition', async () => {
    // Two empty ticks (initial + first interval), then populated. After the
    // populated tick the interval must be cleared inside the tick body — any
    // further advanceTimersByTime() should NOT bump the call count.
    mockApi.feedsStatus
      .mockResolvedValueOnce(EMPTY_STATUS)
      .mockResolvedValueOnce(EMPTY_STATUS)
      .mockResolvedValueOnce(FULL_STATUS);

    render(<EmptyCorpusBanner isAdmin={true} />);
    await act(async () => { await Promise.resolve(); });
    expect(mockApi.feedsStatus).toHaveBeenCalledTimes(1);

    // tick 1 — still empty
    await act(async () => {
      vi.advanceTimersByTime(10_000);
      await Promise.resolve();
    });
    expect(mockApi.feedsStatus).toHaveBeenCalledTimes(2);

    // tick 2 — populated; clearInterval fires inside the tick
    await act(async () => {
      vi.advanceTimersByTime(10_000);
      await Promise.resolve();
    });
    expect(mockApi.feedsStatus).toHaveBeenCalledTimes(3);

    // Advance another 30s — no further ticks because the interval is dead.
    await act(async () => {
      vi.advanceTimersByTime(30_000);
      await Promise.resolve();
    });
    expect(mockApi.feedsStatus).toHaveBeenCalledTimes(3);
  });

  // --- New cases for localStorage persistence (Task 2.3) ---

  it('(h) localStorage fast-path — button disabled immediately; backend confirms running', async () => {
    localStorage.setItem('castellum.sync.inFlight', 'true');
    mockApi.syncStatus.mockResolvedValue({ running: true, startedAt: '2026-05-26T00:00:00Z' });

    render(<EmptyCorpusBanner isAdmin={true} />);

    // Before any microtask flush the initial state from localStorage applies
    expect(screen.getByRole('button', { name: /Syncing/i })).toBeDisabled();

    // After microtask: backend confirmed running — still disabled
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByRole('button', { name: /Syncing/i })).toBeDisabled();
  });

  it('(i) localStorage stale — backend reports not running; button re-enabled and localStorage cleared', async () => {
    localStorage.setItem('castellum.sync.inFlight', 'true');
    mockApi.syncStatus.mockResolvedValue({ running: false, startedAt: null });

    render(<EmptyCorpusBanner isAdmin={true} />);

    // Flush microtasks so mount-confirm useEffect resolves
    await act(async () => { await Promise.resolve(); });

    expect(screen.getByRole('button', { name: /Sync NVD/i })).not.toBeDisabled();
    expect(localStorage.getItem('castellum.sync.inFlight')).toBeNull();
  });

  it('(j) polled transition — after 5s poll reports not running, button re-enabled and interval cleared', async () => {
    localStorage.setItem('castellum.sync.inFlight', 'true');

    // First syncStatus (mount confirm) → still running; subsequent calls → not running
    mockApi.syncStatus
      .mockResolvedValueOnce({ running: true, startedAt: '2026-05-26T00:00:00Z' })
      .mockResolvedValue({ running: false, startedAt: null });

    render(<EmptyCorpusBanner isAdmin={true} />);

    // Flush mount confirm — backend says running
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByRole('button', { name: /Syncing/i })).toBeDisabled();

    const callsAfterMount = mockApi.syncStatus.mock.calls.length;

    // Advance 5s — the poll fires, backend says not running
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });

    expect(screen.getByRole('button', { name: /Sync NVD/i })).not.toBeDisabled();
    expect(localStorage.getItem('castellum.sync.inFlight')).toBeNull();

    // Advance another 5s — no further syncStatus calls (interval was cleared)
    const callsAfterTransition = mockApi.syncStatus.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(mockApi.syncStatus.mock.calls.length).toBe(callsAfterTransition);
    expect(mockApi.syncStatus.mock.calls.length).toBeGreaterThan(callsAfterMount);
  });
});
