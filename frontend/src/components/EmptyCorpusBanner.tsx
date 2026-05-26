import { useEffect, useState } from 'react';
import { api } from '../api/client';
import type { FeedsStatusDto } from '../api/types';

interface Props {
  isAdmin: boolean;
}

const isEmpty = (s: FeedsStatusDto | null): boolean =>
  s === null ||
  s.nvd.rowCount === 0 ||
  s.epss.rowCount === 0 ||
  s.kev.entryCount === 0;

/**
 * Sticky banner displayed when one or more threat-intelligence feeds are empty.
 *
 * Polling: polls {@code GET /api/risk/feeds/status} every 10 seconds while any of
 * {@code nvd.rowCount}, {@code epss.rowCount}, or {@code kev.rowCount} is 0. The
 * moment all three counts go non-zero the interval is cleared inside the tick
 * itself — previously the {@code if (!isEmpty(status)) return null} short-circuit
 * only unmounted the JSX, leaving the {@code setInterval} firing for the life of
 * the parent shell.
 *
 * Admin users see a "Sync NVD + EPSS + KEV" button that POSTs to
 * {@code POST /api/admin/initial-sync} and switches to a disabled "Syncing…" state.
 * Viewer users see the informational text only — no button.
 */
export function EmptyCorpusBanner({ isAdmin }: Props) {
  const [status, setStatus] = useState<FeedsStatusDto | null>(null);
  const [syncInFlight, setSyncInFlight] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let id: ReturnType<typeof setInterval> | null = null;
    let cancelled = false;

    const tick = async () => {
      try {
        const result = await api.feedsStatus();
        if (cancelled) return;
        setStatus(result);
        // The instant all three feeds report non-zero rowCount we kill the
        // poll. The component will also unmount via the !isEmpty short-circuit
        // below, but clearing here avoids a stale tick firing in the gap
        // between state-commit and unmount.
        if (!isEmpty(result) && id !== null) {
          clearInterval(id);
          id = null;
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'feeds/status failed');
        }
      }
    };

    void tick();
    id = setInterval(tick, 10_000);

    return () => {
      cancelled = true;
      if (id !== null) {
        clearInterval(id);
        id = null;
      }
    };
  }, []);

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
