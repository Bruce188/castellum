import { useEffect, useState } from 'react';
import { api } from '../api/client';
import type { Scan } from '../api/types';

const STORAGE_KEY = 'castellum.lastScanId';

function readStoredId(): number | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const n = Number(raw);
    return Number.isInteger(n) ? n : null;
  } catch {
    return null;
  }
}

export function useScanStatus(scanId: number | null): Scan | null {
  const initialId = scanId ?? readStoredId();
  const [scan, setScan] = useState<Scan | null>(null);

  useEffect(() => {
    const id = scanId ?? readStoredId();
    if (id === null) return;

    if (scanId !== null) {
      try { window.localStorage.setItem(STORAGE_KEY, String(scanId)); } catch { /* noop */ }
    }
    let cancelled = false;
    let handle: number | null = null;

    const tick = async () => {
      try {
        const s = await api.getScan(id);
        if (cancelled) return;
        setScan(s);
        if (s.status === 'COMPLETED' || s.status === 'FAILED') {
          if (handle !== null) window.clearInterval(handle);
          try { window.localStorage.removeItem(STORAGE_KEY); } catch { /* noop */ }
        }
      } catch {
        // swallow — next tick retries
      }
    };

    void tick();
    handle = window.setInterval(tick, 5000);
    return () => {
      cancelled = true;
      if (handle !== null) window.clearInterval(handle);
    };
  }, [scanId]);

  // initialId surfaced via state on first paint when arg is null.
  useEffect(() => {
    if (scanId === null && initialId !== null && scan === null) {
      void api.getScan(initialId).then(s => setScan(s)).catch(() => { /* noop */ });
    }
  }, [scanId, initialId, scan]);

  return scan;
}
