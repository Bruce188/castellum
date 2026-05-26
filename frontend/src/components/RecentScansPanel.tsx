import { useEffect, useRef, useState } from 'react';
import { api } from '../api/client';
import type { Scan, ScanStatus } from '../api/types';

const ACTIVE_POLL_MS = 5_000;
const IDLE_POLL_MS = 30_000;

function isActive(status: ScanStatus) {
  return status === 'PENDING' || status === 'RUNNING';
}

function statusBadge(status: ScanStatus) {
  switch (status) {
    case 'PENDING':
      return 'bg-blue-100 text-blue-800';
    case 'RUNNING':
      return 'bg-amber-100 text-amber-800';
    case 'COMPLETE':
      return 'bg-green-100 text-green-800';
    case 'FAILED':
      return 'bg-red-100 text-red-800';
    default:
      return 'bg-gray-100 text-gray-800';
  }
}

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return `${h}h ago`;
}

interface Props {
  latestSubmittedId?: number;
}

export function RecentScansPanel({ latestSubmittedId }: Props) {
  const [scans, setScans] = useState<Scan[]>([]);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const hiddenRef = useRef(document.hidden);

  function clearTimer() {
    if (timerRef.current !== null) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  }

  async function fetchScans() {
    try {
      const page = await api.listScans(10);
      setScans(page.content);
    } catch {
      // silently ignore — don't crash the panel on network errors
    }
  }

  function schedulePolling(scanList: Scan[]) {
    clearTimer();
    if (hiddenRef.current) return;
    const hasActive = scanList.some(s => isActive(s.status));
    const interval = hasActive ? ACTIVE_POLL_MS : IDLE_POLL_MS;
    timerRef.current = setInterval(async () => {
      await fetchScans();
      // re-read updated state via functional update to decide next interval
      setScans(prev => {
        schedulePolling(prev);
        return prev;
      });
    }, interval);
  }

  // Initial fetch + polling setup
  useEffect(() => {
    let mounted = true;

    async function init() {
      try {
        const page = await api.listScans(10);
        if (!mounted) return;
        setScans(page.content);
        schedulePolling(page.content);
      } catch {
        if (mounted) schedulePolling([]);
      }
    }

    void init();

    function onVisibility() {
      hiddenRef.current = document.hidden;
      if (document.hidden) {
        clearTimer();
      } else {
        // resume: fetch immediately then re-schedule
        fetchScans().then(() => {
          setScans(prev => {
            schedulePolling(prev);
            return prev;
          });
        });
      }
    }

    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      mounted = false;
      clearTimer();
      document.removeEventListener('visibilitychange', onVisibility);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Re-schedule whenever scans list changes (status transitions affect cadence)
  useEffect(() => {
    schedulePolling(scans);
    return clearTimer;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scans]);

  // Optimistic insert when parent passes a freshly-submitted scan id
  useEffect(() => {
    if (latestSubmittedId == null) return;
    setScans(prev => {
      const already = prev.some(s => s.id === latestSubmittedId);
      if (already) return prev;
      const optimistic: Scan = {
        id: latestSubmittedId,
        cidr: '…',
        scanType: 'PING_SWEEP',
        status: 'PENDING',
        requestedAt: new Date().toISOString(),
        completedAt: null,
      };
      return [optimistic, ...prev].slice(0, 10);
    });
    // immediately fetch to replace optimistic row
    void fetchScans();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [latestSubmittedId]);

  if (scans.length === 0) return null;

  return (
    <section
      aria-label="Recent scans"
      className="px-4 py-2 border-b border-gray-200 bg-white overflow-x-auto"
    >
      <div className="flex flex-col gap-1 min-w-max">
        {scans.map(scan => (
          <div key={scan.id} className="flex items-center gap-3 text-xs text-gray-700">
            <span className="font-mono text-gray-500 w-10 text-right">#{scan.id}</span>
            <span className="font-mono w-32">{scan.cidr}</span>
            <span className="w-28 text-gray-500">{scan.scanType}</span>
            <span
              className={`px-2 py-0.5 rounded-full font-semibold text-[11px] w-20 text-center ${statusBadge(scan.status)}`}
            >
              {scan.status}
            </span>
            <span className="text-gray-400 w-16 text-right">
              {relativeTime(scan.requestedAt)}
            </span>
            {scan.retryCount !== undefined && scan.retryCount > 0 && (
              <span
                className="px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-amber-100 text-amber-800"
                title={`Auto-retry attempt ${scan.retryCount}/2`}
              >
                retry {scan.retryCount}/2
              </span>
            )}
            {scan.status === 'FAILED' && scan.failureReason && (
              <span
                className="text-red-500 truncate max-w-[200px]"
                title={scan.failureReason}
              >
                {scan.failureReason.length > 60
                  ? scan.failureReason.slice(0, 60) + '…'
                  : scan.failureReason}
              </span>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}
