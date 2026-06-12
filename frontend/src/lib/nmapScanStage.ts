/**
 * Nmap scan stage adapter.
 * Pure-TS — no React, no direct fetch. Client functions injected via NmapStageDeps.
 */

import type { ScanType, ScanDetail } from '../api/types';
import type { StageRunner, StageContext } from './unifiedScan';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface NmapStageDeps {
  triggerScan: (req: { cidr: string; type: ScanType }) => Promise<{ id: number }>;
  getScanDetail: (id: number) => Promise<ScanDetail>;
  pollMs?: number;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

const DEFAULT_POLL_MS = 5000;

/** Returns a Promise that resolves after `ms` milliseconds (fake-timer compatible). */
function delay(ms: number): Promise<void> {
  return new Promise<void>((resolve) => setTimeout(resolve, ms));
}

export function makeNmapStage(type: ScanType, deps: NmapStageDeps): StageRunner {
  const pollMs = deps.pollMs ?? DEFAULT_POLL_MS;

  return async function runNmapStage(ctx: StageContext): Promise<void> {
    // 1. Submit the scan — propagate any error (including 429) unchanged.
    const { id } = await deps.triggerScan({ cidr: ctx.cidr, type });

    // 2. Poll loop.
    // First iteration: delay 0 (fires on advanceTimersByTimeAsync(0)).
    // Subsequent iterations: delay pollMs.
    let firstPoll = true;

    while (true) {
      await delay(firstPoll ? 0 : pollMs);
      firstPoll = false;

      // Check abort before calling getScanDetail.
      if (ctx.signal?.aborted) {
        return;
      }

      const detail = await deps.getScanDetail(id);

      // Report progress for every poll result. Chunk fields are forwarded only
      // when the polled detail carries them — legacy details emit none.
      ctx.report({
        scanStatus: detail.status,
        discoveredDeviceIds: detail.discoveredDeviceIds,
        ...(detail.chunksTotal !== undefined ? { chunksTotal: detail.chunksTotal } : {}),
        ...(detail.chunksDone !== undefined ? { chunksDone: detail.chunksDone } : {}),
      });

      if (detail.status === 'COMPLETE') {
        return;
      }

      if (detail.status === 'FAILED') {
        const msg =
          detail.failureReason != null && detail.failureReason !== ''
            ? detail.failureReason
            : 'Scan failed';
        throw new Error(msg);
      }

      // PENDING or RUNNING — check abort then continue to next poll.
      if (ctx.signal?.aborted) {
        return;
      }
    }
  };
}
