import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { FeedSyncPanel } from '../components/FeedSyncPanel';
import { api } from '../api/client';

vi.mock('../api/client', () => ({
  api: {
    feedsStatus: vi.fn(),
    syncStatus: vi.fn(),
    triggerInitialSync: vi.fn(),
  },
}));

const feedsStatus = vi.mocked(api.feedsStatus);
const syncStatus = vi.mocked(api.syncStatus);
const triggerInitialSync = vi.mocked(api.triggerInitialSync);

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

beforeEach(() => {
  feedsStatus.mockReset();
  syncStatus.mockReset();
  triggerInitialSync.mockReset();
  feedsStatus.mockResolvedValue(FULL_CORPUS_FEEDS);
  syncStatus.mockResolvedValue(STATUS_IDLE);
  triggerInitialSync.mockResolvedValue({ status: 'started', startedAt: new Date().toISOString() });
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
      const btn = screen.getByRole('button', { name: /Syncing/i });
      expect(btn).toBeDisabled();
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
});
