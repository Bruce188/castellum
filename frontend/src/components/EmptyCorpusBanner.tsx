import { useEffect, useState, useCallback } from 'react';
import { api } from '../api/client';
import type { FeedsStatusDto } from '../api/types';

interface Props {
  isAdmin: boolean;
}

/**
 * Sticky banner displayed when one or more threat-intelligence feeds are empty.
 *
 * Polling: polls {@code GET /api/risk/feeds/status} every 10 seconds while any of
 * {@code nvd.rowCount}, {@code epss.rowCount}, or {@code kev.rowCount} is 0. Once all
 * three are non-zero the interval is cleared and the banner unmounts (returns null).
 *
 * Admin users see a "Sync NVD + EPSS + KEV" button that POSTs to
 * {@code POST /api/admin/initial-sync} and switches to a disabled "Syncing…" state.
 * Viewer users see the informational text only — no button.
 */
export function EmptyCorpusBanner({ isAdmin }: Props) {
  const [status, setStatus] = useState<FeedsStatusDto | null>(null);
  const [syncInFlight, setSyncInFlight] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isEmpty = (s: FeedsStatusDto | null): boolean =>
    s === null ||
    s.nvd.rowCount === 0 ||
    s.epss.rowCount === 0 ||
    s.kev.entryCount === 0;

  const fetchStatus = useCallback(async () => {
    try {
      const result = await api.feedsStatus();
      setStatus(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'feeds/status failed');
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const id = setInterval(() => {
      fetchStatus();
    }, 10_000);
    return () => clearInterval(id);
  }, [fetchStatus]);

  // Once all three counts are non-zero the banner is not needed
  if (status !== null && !isEmpty(status)) {
    return null;
  }

  async function handleSync() {
    setSyncInFlight(true);
    setError(null);
    try {
      await api.triggerInitialSync();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'sync trigger failed');
      setSyncInFlight(false);
    }
    // Keep spinner until next poll cycle confirms feeds are populated
  }

  return (
    <div className="bg-amber-50 border-b border-amber-200 px-4 py-3 flex items-center gap-4">
      <span className="text-amber-800 text-sm flex-1">
        Threat intelligence feeds are empty. Sync NVD + EPSS + KEV to enable risk scoring.
      </span>
      {error && (
        <span className="text-red-600 text-sm">{error}</span>
      )}
      {isAdmin && (
        <button
          type="button"
          disabled={syncInFlight}
          onClick={handleSync}
          className="px-3 py-1 text-sm bg-amber-600 text-white rounded hover:bg-amber-700 disabled:opacity-60 disabled:cursor-not-allowed"
        >
          {syncInFlight ? 'Syncing…' : 'Sync NVD + EPSS + KEV'}
        </button>
      )}
    </div>
  );
}
