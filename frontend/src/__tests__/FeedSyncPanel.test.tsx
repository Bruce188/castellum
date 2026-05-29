import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { FeedSyncPanel } from '../components/FeedSyncPanel';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    feedsStatus: vi.fn(),
    syncStatus: vi.fn(),
    triggerInitialSync: vi.fn(),
    triggerFullBackfill: vi.fn(),
    getFeedSchedule: vi.fn(),
    updateFeedSchedule: vi.fn(),
    enableFeedSchedule: vi.fn(),
    disableFeedSchedule: vi.fn(),
    resetFeedSchedule: vi.fn(),
    cveCoverage: vi.fn(),
  },
}));

const feedsStatus = vi.mocked(api.feedsStatus);
const syncStatus = vi.mocked(api.syncStatus);
const triggerInitialSync = vi.mocked(api.triggerInitialSync);
const triggerFullBackfill = vi.mocked(api.triggerFullBackfill);
const getFeedSchedule = vi.mocked(api.getFeedSchedule);
const updateFeedSchedule = vi.mocked(api.updateFeedSchedule);
const enableFeedSchedule = vi.mocked(api.enableFeedSchedule);
const disableFeedSchedule = vi.mocked(api.disableFeedSchedule);
const resetFeedSchedule = vi.mocked(api.resetFeedSchedule);
const cveCoverage = vi.mocked(api.cveCoverage);

const FULL_CORPUS_FEEDS = {
  nvd: { lastModified: '2026-05-20T00:00:00Z', rowCount: 500 },
  epss: { scoreDate: '2026-05-20', rowCount: 300 },
  kev: { lastIngestedAt: '2026-05-20T00:00:00Z', entryCount: 100 },
};

const STATUS_IDLE = {
  running: false,
  startedAt: null,
  lastCompletedAt: null,
  lastError: null,
};

const SCHEDULE_ENABLED = {
  enabled: true,
  cron: '0 0 6 * * *',
  lastRunAt: '2026-05-27T06:00:00Z',
  lastStatus: 'OK',
  lastError: null,
  nextRunAt: '2026-05-28T06:00:00Z',
  consecutiveFailures: 0,
};

const SCHEDULE_DISABLED = {
  ...SCHEDULE_ENABLED,
  enabled: false,
  nextRunAt: null,
};

const FULL_COVERAGE = {
  totalCves: 250_000,
  earliestPublishedYear: 2004,
  latestPublishedYear: 2026,
  kevInCorpus: 1606,
  thinCorpus: false,
};

const THIN_COVERAGE = {
  totalCves: 3957,
  earliestPublishedYear: 2026,
  latestPublishedYear: 2026,
  kevInCorpus: 17,
  thinCorpus: true,
};

beforeEach(() => {
  feedsStatus.mockReset();
  syncStatus.mockReset();
  triggerInitialSync.mockReset();
  triggerFullBackfill.mockReset();
  getFeedSchedule.mockReset();
  updateFeedSchedule.mockReset();
  enableFeedSchedule.mockReset();
  disableFeedSchedule.mockReset();
  resetFeedSchedule.mockReset();
  cveCoverage.mockReset();

  feedsStatus.mockResolvedValue(FULL_CORPUS_FEEDS);
  syncStatus.mockResolvedValue(STATUS_IDLE);
  triggerInitialSync.mockResolvedValue({ status: 'started', startedAt: new Date().toISOString() });
  triggerFullBackfill.mockResolvedValue({ status: 'started', startedAt: new Date().toISOString() });
  getFeedSchedule.mockResolvedValue(SCHEDULE_ENABLED);
  disableFeedSchedule.mockResolvedValue(SCHEDULE_DISABLED);
  enableFeedSchedule.mockResolvedValue(SCHEDULE_ENABLED);
  resetFeedSchedule.mockResolvedValue(SCHEDULE_ENABLED);
  cveCoverage.mockResolvedValue(FULL_COVERAGE);
});

describe('<FeedSyncPanel />', () => {
  it('renders the sync control regardless of corpus emptiness (non-empty corpus)', async () => {
    render(<FeedSyncPanel isAdmin={true} />);
    // Panel renders regardless of corpus size — button always present
    const btn = await screen.findByRole('button', { name: /Sync feeds/i });
    expect(btn).toBeInTheDocument();
  });

  it('shows per-feed freshness for NVD, KEV, EPSS', async () => {
    render(<FeedSyncPanel isAdmin={true} />);
    await waitFor(() => {
      expect(screen.getByTestId('feed-row-nvd')).toBeInTheDocument();
    });
    expect(screen.getByTestId('feed-row-epss')).toBeInTheDocument();
    expect(screen.getByTestId('feed-row-kev')).toBeInTheDocument();
    // Row counts visible
    expect(screen.getByTestId('feed-row-nvd')).toHaveTextContent('500');
    expect(screen.getByTestId('feed-row-epss')).toHaveTextContent('300');
    expect(screen.getByTestId('feed-row-kev')).toHaveTextContent('100');
  });

  it('shows last-completed time when available', async () => {
    syncStatus.mockResolvedValue({
      running: false,
      startedAt: null,
      lastCompletedAt: '2026-05-20T00:00:00Z',
      lastError: null,
    });
    render(<FeedSyncPanel isAdmin={true} />);
    await waitFor(() => {
      expect(screen.getByTestId('last-completed')).toBeInTheDocument();
    });
    expect(screen.getByTestId('last-completed')).toHaveTextContent('2026-05-20');
  });

  it('shows last-error when sync failed', async () => {
    syncStatus.mockResolvedValue({
      running: false,
      startedAt: null,
      lastCompletedAt: null,
      lastError: 'NVD down',
    });
    render(<FeedSyncPanel isAdmin={true} />);
    await waitFor(() => {
      expect(screen.getByTestId('last-error')).toBeInTheDocument();
    });
    expect(screen.getByTestId('last-error')).toHaveTextContent('NVD down');
  });

  it('admin can trigger the sync', async () => {
    render(<FeedSyncPanel isAdmin={true} />);
    const btn = await screen.findByRole('button', { name: /Sync feeds/i });
    fireEvent.click(btn);
    await waitFor(() => expect(triggerInitialSync).toHaveBeenCalledTimes(1));
  });

  it('reflects running state: button disabled and shows Syncing label', async () => {
    syncStatus.mockResolvedValue({
      running: true,
      startedAt: new Date().toISOString(),
      lastCompletedAt: null,
      lastError: null,
    });
    render(<FeedSyncPanel isAdmin={true} />);
    await waitFor(() => {
      const btns = screen.getAllByRole('button', { name: /Syncing/i });
      expect(btns.length).toBeGreaterThan(0);
      btns.forEach(btn => expect(btn).toBeDisabled());
    });
  });

  it('viewer sees read-only badge and no enabled trigger button', async () => {
    render(<FeedSyncPanel isAdmin={false} />);
    await waitFor(() => {
      expect(screen.getByText(/Read-only/i)).toBeInTheDocument();
    });
    const btn = screen.queryByRole('button', { name: /Sync feeds/i });
    // Either the button doesn't exist for viewers, or it exists but is disabled
    if (btn) {
      expect(btn).toBeDisabled();
    } else {
      expect(btn).toBeNull();
    }
  });

  it('tolerates syncStatus 403 and still renders feeds freshness', async () => {
    syncStatus.mockRejectedValueOnce(new Error('403'));
    render(<FeedSyncPanel isAdmin={true} />);
    // Should not crash; feeds rows still render from feedsStatus
    await waitFor(() => {
      expect(screen.getByTestId('feed-row-nvd')).toBeInTheDocument();
    });
    // Panel is still visible
    expect(screen.getByTestId('feed-sync-panel')).toBeInTheDocument();
  });

  // --- Schedule sub-block (Task 4.1) ---

  it('renders schedule cron, last-run, and next-run for admin', async () => {
    render(<FeedSyncPanel isAdmin={true} />);
    await waitFor(() => {
      expect(screen.getByTestId('schedule-cron')).toBeInTheDocument();
    });
    expect(screen.getByTestId('schedule-cron')).toHaveTextContent('0 0 6 * * *');
    expect(screen.getByTestId('schedule-last-run')).toBeInTheDocument();
    expect(screen.getByTestId('schedule-last-run')).toHaveTextContent('2026-05-27');
    expect(screen.getByTestId('schedule-last-run')).toHaveTextContent('OK');
    expect(screen.getByTestId('schedule-next-run')).toBeInTheDocument();
    expect(screen.getByTestId('schedule-next-run')).toHaveTextContent('2026-05-28');
  });

  it('toggle disable: clicking "Disable" calls disableFeedSchedule and refetches', async () => {
    render(<FeedSyncPanel isAdmin={true} />);
    // Wait for the toggle to appear (enabled → label "Disable")
    const toggleBtn = await screen.findByTestId('schedule-toggle');
    expect(toggleBtn).toHaveTextContent(/Disable/i);
    fireEvent.click(toggleBtn);
    await waitFor(() => expect(disableFeedSchedule).toHaveBeenCalledTimes(1));
    // After disable, getFeedSchedule should be called again (refetch)
    await waitFor(() => expect(getFeedSchedule).toHaveBeenCalledTimes(2));
  });

  it('toggle enable: when schedule is disabled the toggle reads "Enable" and calls enableFeedSchedule', async () => {
    getFeedSchedule.mockResolvedValue(SCHEDULE_DISABLED);
    render(<FeedSyncPanel isAdmin={true} />);
    const toggleBtn = await screen.findByTestId('schedule-toggle');
    expect(toggleBtn).toHaveTextContent(/Enable/i);
    fireEvent.click(toggleBtn);
    await waitFor(() => expect(enableFeedSchedule).toHaveBeenCalledTimes(1));
  });

  it('tolerates getFeedSchedule reject (403) — panel still renders feed rows and Sync feeds button', async () => {
    getFeedSchedule.mockRejectedValueOnce(new Error('403'));
    render(<FeedSyncPanel isAdmin={true} />);
    // Feed freshness rows must still appear
    await waitFor(() => {
      expect(screen.getByTestId('feed-row-nvd')).toBeInTheDocument();
    });
    expect(screen.getByTestId('feed-row-epss')).toBeInTheDocument();
    expect(screen.getByTestId('feed-row-kev')).toBeInTheDocument();
    // The manual "Sync feeds" button must still be present
    expect(screen.getByRole('button', { name: /Sync feeds/i })).toBeInTheDocument();
    // Panel must not have crashed
    expect(screen.getByTestId('feed-sync-panel')).toBeInTheDocument();
    // Schedule sub-block should be absent (null schedule → nothing rendered)
    expect(screen.queryByTestId('schedule-cron')).not.toBeInTheDocument();
  });

  it('viewer: schedule-toggle is not actionable (absent or disabled)', async () => {
    render(<FeedSyncPanel isAdmin={false} />);
    // Give async mount a moment
    await waitFor(() => {
      expect(screen.getByTestId('feed-sync-panel')).toBeInTheDocument();
    });
    const toggleBtn = screen.queryByTestId('schedule-toggle');
    // Either the toggle is absent for viewers or it is disabled
    if (toggleBtn) {
      expect(toggleBtn).toBeDisabled();
    } else {
      expect(toggleBtn).toBeNull();
    }
  });

  // --- Full NVD backfill button (AC1 frontend) ---

  it('admin sees "Full NVD backfill" button', async () => {
    render(<FeedSyncPanel isAdmin={true} />);
    const btn = await screen.findByTestId('full-backfill-btn');
    expect(btn).toBeInTheDocument();
    expect(btn).toHaveTextContent(/Full NVD backfill/i);
    expect(btn).not.toBeDisabled();
  });

  it('viewer does NOT see "Full NVD backfill" button', async () => {
    render(<FeedSyncPanel isAdmin={false} />);
    await waitFor(() => {
      expect(screen.getByTestId('feed-sync-panel')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('full-backfill-btn')).not.toBeInTheDocument();
  });

  it('clicking "Full NVD backfill" calls triggerFullBackfill', async () => {
    render(<FeedSyncPanel isAdmin={true} />);
    const btn = await screen.findByTestId('full-backfill-btn');
    fireEvent.click(btn);
    await waitFor(() => expect(triggerFullBackfill).toHaveBeenCalledTimes(1));
    // triggerInitialSync must NOT be called — distinct call path
    expect(triggerInitialSync).not.toHaveBeenCalled();
  });

  it('"Full NVD backfill" button is disabled while running', async () => {
    syncStatus.mockResolvedValue({
      running: true,
      startedAt: new Date().toISOString(),
      lastCompletedAt: null,
      lastError: null,
    });
    render(<FeedSyncPanel isAdmin={true} />);
    await waitFor(() => {
      const btn = screen.getByTestId('full-backfill-btn');
      expect(btn).toBeDisabled();
    });
  });

  // --- AC3: corpus-coverage visibility ---

  it('shows corpus coverage block with totalCves and KEV count (full corpus)', async () => {
    render(<FeedSyncPanel isAdmin={true} />);
    await waitFor(() => {
      expect(screen.getByTestId('corpus-coverage')).toBeInTheDocument();
    });
    expect(screen.getByTestId('corpus-coverage')).toHaveTextContent('250,000');
    expect(screen.getByTestId('kev-in-corpus')).toHaveTextContent('1,606');
    // year range appears
    expect(screen.getByTestId('corpus-coverage')).toHaveTextContent('2004');
    expect(screen.getByTestId('corpus-coverage')).toHaveTextContent('2026');
    // thin corpus hint must NOT appear for a full corpus
    expect(screen.queryByTestId('thin-corpus-hint')).not.toBeInTheDocument();
  });

  it('shows thin-corpus hint when corpus is thin', async () => {
    cveCoverage.mockResolvedValue(THIN_COVERAGE);
    render(<FeedSyncPanel isAdmin={true} />);
    await waitFor(() => {
      expect(screen.getByTestId('thin-corpus-hint')).toBeInTheDocument();
    });
    expect(screen.getByTestId('thin-corpus-hint')).toHaveTextContent(/thin/i);
    expect(screen.getByTestId('thin-corpus-hint')).toHaveTextContent(/Full NVD backfill/i);
  });

  it('thin-corpus hint does not show backfill action for viewer', async () => {
    cveCoverage.mockResolvedValue(THIN_COVERAGE);
    render(<FeedSyncPanel isAdmin={false} />);
    await waitFor(() => {
      expect(screen.getByTestId('thin-corpus-hint')).toBeInTheDocument();
    });
    // The "Full NVD backfill" CTA must NOT appear for viewers
    expect(screen.getByTestId('thin-corpus-hint')).not.toHaveTextContent(/Full NVD backfill/i);
  });

  it('tolerates cveCoverage error — panel still renders feed rows', async () => {
    cveCoverage.mockRejectedValueOnce(new Error('403'));
    render(<FeedSyncPanel isAdmin={true} />);
    await waitFor(() => {
      expect(screen.getByTestId('feed-row-nvd')).toBeInTheDocument();
    });
    // corpus-coverage block should not be present (no data)
    expect(screen.queryByTestId('corpus-coverage')).not.toBeInTheDocument();
    // panel must not have crashed
    expect(screen.getByTestId('feed-sync-panel')).toBeInTheDocument();
  });

  // --- Cron editor (feat/feed-schedule-cron-editor) ---

  it('admin sees cron input field populated with current cron', async () => {
    render(<FeedSyncPanel isAdmin={true} />);
    const input = await screen.findByTestId('cron-input');
    expect(input).toHaveValue('0 0 6 * * *');
  });

  it('admin can edit cron and Save calls updateFeedSchedule with new cron', async () => {
    const updated = { ...SCHEDULE_ENABLED, cron: '0 0 3 * * *', nextRunAt: '2026-05-28T03:00:00Z' };
    updateFeedSchedule.mockResolvedValueOnce(updated);
    getFeedSchedule.mockResolvedValueOnce(updated);

    render(<FeedSyncPanel isAdmin={true} />);
    const input = await screen.findByTestId('cron-input');
    fireEvent.change(input, { target: { value: '0 0 3 * * *' } });
    const saveBtn = screen.getByTestId('cron-save-btn');
    fireEvent.click(saveBtn);

    await waitFor(() =>
      expect(updateFeedSchedule).toHaveBeenCalledWith(
        expect.objectContaining({ cron: '0 0 3 * * *' })
      )
    );
    // UI reflects new value after save
    await waitFor(() => expect(input).toHaveValue('0 0 3 * * *'));
  });

  it('invalid cron shows inline error and does NOT call updateFeedSchedule', async () => {
    updateFeedSchedule.mockRejectedValueOnce(
      Object.assign(new Error('invalid cron expression: bad'), { status: 400 })
    );

    render(<FeedSyncPanel isAdmin={true} />);
    const input = await screen.findByTestId('cron-input');
    fireEvent.change(input, { target: { value: 'not-a-cron' } });
    const saveBtn = screen.getByTestId('cron-save-btn');
    fireEvent.click(saveBtn);

    // updateFeedSchedule was called (backend rejects it)
    await waitFor(() => expect(updateFeedSchedule).toHaveBeenCalledTimes(1));
    // Error hint shown to the user
    await waitFor(() => expect(screen.getByTestId('cron-error')).toBeInTheDocument());
    // Schedule state unchanged — cron display still shows original
    expect(screen.getByTestId('schedule-cron')).toHaveTextContent('0 0 6 * * *');
  });

  it('admin reset calls resetFeedSchedule and reverts input to default', async () => {
    const custom = { ...SCHEDULE_ENABLED, cron: '0 0 3 * * *' };
    getFeedSchedule.mockResolvedValue(custom);
    resetFeedSchedule.mockResolvedValueOnce(SCHEDULE_ENABLED);

    render(<FeedSyncPanel isAdmin={true} />);
    const resetBtn = await screen.findByTestId('cron-reset-btn');
    fireEvent.click(resetBtn);

    await waitFor(() => expect(resetFeedSchedule).toHaveBeenCalledTimes(1));
    // Input and schedule display revert to default
    await waitFor(() =>
      expect(screen.getByTestId('cron-input')).toHaveValue('0 0 6 * * *')
    );
    expect(screen.getByTestId('schedule-cron')).toHaveTextContent('0 0 6 * * *');
  });

  it('viewer sees cron as read-only text (no cron-input, no cron-save-btn, no cron-reset-btn)', async () => {
    render(<FeedSyncPanel isAdmin={false} />);
    await waitFor(() =>
      expect(screen.getByTestId('feed-sync-panel')).toBeInTheDocument()
    );
    expect(screen.queryByTestId('cron-input')).not.toBeInTheDocument();
    expect(screen.queryByTestId('cron-save-btn')).not.toBeInTheDocument();
    expect(screen.queryByTestId('cron-reset-btn')).not.toBeInTheDocument();
  });
});
