import { useEffect, useRef, useState } from 'react';
import { api } from '../api/client';
import type { FeedScheduleDto, FeedsStatusDto, SyncStatusResponse } from '../api/types';
import {
  freshnessTier,
  FRESHNESS_DOT_CLASSES,
} from '../lib/freshness';

interface Props {
  isAdmin: boolean;
}

const POLL_INTERVAL_MS = 5000;

/**
 * ADMIN-gated feed-sync control panel, always mounted in Settings regardless of corpus size.
 *
 * <p>Shows per-feed freshness (NVD/KEV/EPSS rowCount + lastModified via existing
 * feeds/status endpoint), the last-completed timestamp and last-error from sync status,
 * and a "Sync feeds" button that triggers the initial-sync endpoint. Polls while running.
 * VIEWERs see the panel read-only (button disabled / absent); the backend enforces RBAC.
 */
export function FeedSyncPanel({ isAdmin }: Props) {
  const [feeds, setFeeds] = useState<FeedsStatusDto | null>(null);
  const [status, setStatus] = useState<SyncStatusResponse | null>(null);
  const [schedule, setSchedule] = useState<FeedScheduleDto | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  function stopPoll() {
    if (pollRef.current !== null) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }

  async function loadStatus() {
    try {
      const s = await api.syncStatus();
      setStatus(s);
      if (!s.running) {
        stopPoll();
        setSubmitting(false);
      }
    } catch {
      // Tolerate 403 for VIEWER — hide outcome line, keep feeds freshness
      stopPoll();
      setSubmitting(false);
    }
  }

  useEffect(() => {
    let cancelled = false;
    api.feedsStatus()
      .then(f => { if (!cancelled) setFeeds(f); })
      .catch(() => { /* keep null — panel still renders */ });
    loadStatus();
    if (isAdmin) {
      api.getFeedSchedule()
        .then(s => { if (!cancelled) setSchedule(s); })
        .catch(() => { /* tolerate 403/non-admin — leave schedule null */ });
    }
    return () => {
      cancelled = true;
      stopPoll();
    };
  }, []);

  async function handleScheduleToggle() {
    if (!schedule) return;
    try {
      if (schedule.enabled) {
        await api.disableFeedSchedule();
      } else {
        await api.enableFeedSchedule();
      }
      const updated = await api.getFeedSchedule();
      setSchedule(updated);
    } catch {
      /* ignore — schedule toggle errors are non-fatal */
    }
  }

  async function handleSync() {
    if (!isAdmin || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      await api.triggerInitialSync();
      // Start polling for completion
      pollRef.current = setInterval(loadStatus, POLL_INTERVAL_MS);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'sync failed');
      setSubmitting(false);
    }
  }

  async function handleFullBackfill() {
    if (!isAdmin || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      await api.triggerFullBackfill();
      // Start polling for completion — same status endpoint tracks progress
      pollRef.current = setInterval(loadStatus, POLL_INTERVAL_MS);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'full backfill failed');
      setSubmitting(false);
    }
  }

  const running = status?.running || submitting;

  return (
    <section
      data-testid="feed-sync-panel"
      className="rounded border border-gray-200 bg-white p-4 mb-4"
    >
      <header className="flex items-baseline justify-between mb-3">
        <h2 className="text-base font-semibold text-gray-800">Feed sync</h2>
        {!isAdmin && (
          <span className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded px-2 py-0.5">
            Read-only — ADMIN required to trigger sync
          </span>
        )}
      </header>

      {/* Per-feed freshness rows */}
      <div className="mb-4 space-y-1">
        {feeds ? (
          <>
            <FeedRow
              testId="feed-row-nvd"
              label="NVD"
              count={feeds.nvd.rowCount}
              timestamp={feeds.nvd.lastModified}
            />
            <FeedRow
              testId="feed-row-epss"
              label="EPSS"
              count={feeds.epss.rowCount}
              timestamp={feeds.epss.scoreDate}
            />
            <FeedRow
              testId="feed-row-kev"
              label="KEV"
              count={feeds.kev.entryCount}
              timestamp={feeds.kev.lastIngestedAt}
            />
          </>
        ) : (
          <p className="text-xs text-gray-400">Loading feed status…</p>
        )}
      </div>

      {/* Sync outcome (only when status loaded — hide on 403/null) */}
      {status && (
        <div className="mb-3 text-xs text-gray-600 space-y-0.5">
          {status.lastCompletedAt && (
            <p data-testid="last-completed">
              Last completed: <span className="font-mono">{status.lastCompletedAt}</span>
            </p>
          )}
          {status.lastError && (
            <p data-testid="last-error" className="text-red-600">
              Last error: {status.lastError}
            </p>
          )}
        </div>
      )}

      {/* Schedule sub-block (only when loaded) */}
      {schedule && (
        <div className="mb-3 text-xs text-gray-600 space-y-0.5">
          <p data-testid="schedule-cron">
            Schedule: <span className="font-mono">{schedule.cron}</span>
          </p>
          <p data-testid="schedule-last-run">
            Last run: <span className="font-mono">{schedule.lastRunAt ? schedule.lastRunAt.substring(0, 10) : '—'}</span>
            {schedule.lastStatus && <span className="ml-1">({schedule.lastStatus})</span>}
          </p>
          <p data-testid="schedule-next-run">
            Next run: <span className="font-mono">{schedule.nextRunAt ? schedule.nextRunAt.substring(0, 10) : '—'}</span>
          </p>
          {isAdmin && (
            <button
              type="button"
              data-testid="schedule-toggle"
              onClick={handleScheduleToggle}
              className="mt-1 px-2 py-0.5 text-xs rounded border border-gray-300 bg-gray-50 hover:bg-gray-100"
            >
              {schedule.enabled ? 'Disable' : 'Enable'}
            </button>
          )}
        </div>
      )}

      {/* Trigger buttons */}
      <div className="flex items-center gap-3 flex-wrap">
        {isAdmin ? (
          <>
            <button
              type="button"
              onClick={handleSync}
              disabled={running}
              className="px-3 py-1 text-sm rounded bg-blue-600 text-white hover:bg-blue-700 disabled:bg-blue-300 disabled:cursor-not-allowed"
            >
              {running ? 'Syncing…' : 'Sync feeds'}
            </button>
            <button
              type="button"
              data-testid="full-backfill-btn"
              onClick={handleFullBackfill}
              disabled={running}
              title="Force a full historical NVD corpus backfill (EPOCH→now). Bypasses the incremental cursor. Takes tens of minutes."
              className="px-3 py-1 text-sm rounded bg-amber-600 text-white hover:bg-amber-700 disabled:bg-amber-300 disabled:cursor-not-allowed"
            >
              {running ? 'Syncing…' : 'Full NVD backfill'}
            </button>
          </>
        ) : (
          <button
            type="button"
            disabled
            className="px-3 py-1 text-sm rounded bg-blue-300 text-white cursor-not-allowed"
          >
            Sync feeds
          </button>
        )}
        {error && (
          <span role="alert" className="text-sm text-red-600">{error}</span>
        )}
      </div>
    </section>
  );
}

interface FeedRowProps {
  testId: string;
  label: string;
  count: number;
  timestamp: string | null;
}

function FeedRow({ testId, label, count, timestamp }: FeedRowProps) {
  const tier = freshnessTier(timestamp);
  return (
    <div
      data-testid={testId}
      className="flex items-center gap-2 text-sm text-gray-700"
    >
      <span
        className={`inline-block w-2 h-2 rounded-full ${FRESHNESS_DOT_CLASSES[tier]}`}
        title={tier}
      />
      <span className="w-12 font-medium">{label}</span>
      <span className="text-gray-500">{count.toLocaleString()} rows</span>
      {timestamp && (
        <span className="text-gray-400 text-xs">{timestamp.substring(0, 10)}</span>
      )}
    </div>
  );
}
