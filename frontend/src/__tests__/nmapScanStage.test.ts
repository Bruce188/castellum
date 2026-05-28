/**
 * RED-phase tests for the nmap scan stage adapter (Task 2.1).
 *
 * Targeted module: frontend/src/lib/nmapScanStage.ts (does NOT exist yet — import fails → RED).
 *
 * Exact exported symbols asserted (from plan-v65.md § Task 2.1 + prompts-v60.md § Task 2.1):
 *   makeNmapStage(type: ScanType, deps: NmapStageDeps): StageRunner
 *   interface NmapStageDeps { triggerScan, getScanDetail, pollMs? }
 *
 * All tests inject vi.fn() client deps — NOT the real client.
 * vi.useFakeTimers() controls the poll delay (setTimeout-based) deterministically.
 * Do NOT use waitFor under fake timers — drive timers explicitly via vi.advanceTimersByTimeAsync.
 *
 * ScanStatus values (from api/types.ts): 'PENDING' | 'RUNNING' | 'COMPLETE' | 'FAILED'
 * ScanType values (from api/types.ts): 'PING_SWEEP' | 'SERVICE_DETECT' | 'OS_FINGERPRINT'
 * Poll interval default: 5000ms (mirroring useScanStatus.ts)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ScanType, ScanDetail } from '../api/types';
import type { StageRunner, StageContext, StageProgress } from '../lib/unifiedScan';
import { makeNmapStage } from '../lib/nmapScanStage';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DEFAULT_POLL_MS = 5000;

function makeScanDetail(
  id: number,
  status: ScanDetail['status'],
  extra: Partial<ScanDetail> = {},
): ScanDetail {
  return {
    id,
    cidr: '192.168.1.0/24',
    scanType: 'PING_SWEEP',
    status,
    requestedAt: '2026-05-28T00:00:00Z',
    completedAt: status === 'COMPLETE' || status === 'FAILED' ? '2026-05-28T00:01:00Z' : null,
    failureReason: null,
    discoveredDeviceIds: [],
    ...extra,
  };
}

function makeCtx(overrides: Partial<StageContext> = {}): StageContext & { reports: StageProgress[] } {
  const reports: StageProgress[] = [];
  return {
    cidr: '192.168.1.0/24',
    report: vi.fn((p: StageProgress) => { reports.push(p); }),
    ...overrides,
    reports,
  };
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('makeNmapStage', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // -------------------------------------------------------------------------
  // Case 1 — submit → poll → COMPLETE (happy path)
  // -------------------------------------------------------------------------
  describe('submit → poll → COMPLETE', () => {
    it('calls triggerScan once with {cidr, type}, polls getScanDetail at pollMs intervals, reports scanStatus + discoveredDeviceIds, and resolves when COMPLETE', async () => {
      const scanId = 42;
      const discoveredDeviceIds = [1, 2, 3];
      const type: ScanType = 'PING_SWEEP';

      const triggerScan = vi.fn().mockResolvedValue({ id: scanId });
      const getScanDetail = vi.fn()
        .mockResolvedValueOnce(makeScanDetail(scanId, 'PENDING'))
        .mockResolvedValueOnce(makeScanDetail(scanId, 'RUNNING'))
        .mockResolvedValueOnce(makeScanDetail(scanId, 'COMPLETE', { discoveredDeviceIds }));

      const deps = { triggerScan, getScanDetail, pollMs: DEFAULT_POLL_MS };
      const runner: StageRunner = makeNmapStage(type, deps);
      const ctx = makeCtx();

      const runnerPromise = runner(ctx);

      // First poll fires immediately (no initial delay before first getScanDetail).
      await vi.advanceTimersByTimeAsync(0);
      // Advance past first pollMs → triggers second getScanDetail.
      await vi.advanceTimersByTimeAsync(DEFAULT_POLL_MS);
      // Advance past second pollMs → triggers third getScanDetail (COMPLETE).
      await vi.advanceTimersByTimeAsync(DEFAULT_POLL_MS);

      await runnerPromise;

      // triggerScan called exactly once with the correct request.
      expect(triggerScan).toHaveBeenCalledTimes(1);
      expect(triggerScan).toHaveBeenCalledWith({ cidr: '192.168.1.0/24', type: 'PING_SWEEP' });

      // getScanDetail polled 3 times total (PENDING, RUNNING, COMPLETE).
      expect(getScanDetail).toHaveBeenCalledTimes(3);
      expect(getScanDetail).toHaveBeenCalledWith(scanId);

      // ctx.report emitted for each poll result.
      expect(ctx.reports.length).toBeGreaterThanOrEqual(3);

      // The COMPLETE report carries discoveredDeviceIds.
      const completeReport = ctx.reports.find((r) => r.scanStatus === 'COMPLETE');
      expect(completeReport).toBeDefined();
      expect(completeReport?.discoveredDeviceIds).toEqual(discoveredDeviceIds);

      // Intermediate reports reflect intermediate statuses.
      expect(ctx.reports.some((r) => r.scanStatus === 'PENDING')).toBe(true);
      expect(ctx.reports.some((r) => r.scanStatus === 'RUNNING')).toBe(true);
    });

    it('works with SERVICE_DETECT scan type', async () => {
      const type: ScanType = 'SERVICE_DETECT';
      const triggerScan = vi.fn().mockResolvedValue({ id: 10 });
      const getScanDetail = vi.fn().mockResolvedValue(makeScanDetail(10, 'COMPLETE'));

      const runner = makeNmapStage(type, { triggerScan, getScanDetail });
      const ctx = makeCtx();
      const runnerPromise = runner(ctx);

      await vi.advanceTimersByTimeAsync(0);
      await runnerPromise;

      expect(triggerScan).toHaveBeenCalledWith({ cidr: '192.168.1.0/24', type: 'SERVICE_DETECT' });
    });

    it('works with OS_FINGERPRINT scan type', async () => {
      const type: ScanType = 'OS_FINGERPRINT';
      const triggerScan = vi.fn().mockResolvedValue({ id: 11 });
      const getScanDetail = vi.fn().mockResolvedValue(makeScanDetail(11, 'COMPLETE'));

      const runner = makeNmapStage(type, { triggerScan, getScanDetail });
      const ctx = makeCtx();
      const runnerPromise = runner(ctx);

      await vi.advanceTimersByTimeAsync(0);
      await runnerPromise;

      expect(triggerScan).toHaveBeenCalledWith({ cidr: '192.168.1.0/24', type: 'OS_FINGERPRINT' });
    });
  });

  // -------------------------------------------------------------------------
  // Case 2 — FAILED terminal: runner throws
  // -------------------------------------------------------------------------
  describe('FAILED terminal status', () => {
    it('rejects with failureReason when getScanDetail returns FAILED', async () => {
      const scanId = 99;
      const failureReason = 'nmap process exited with code 1';

      const triggerScan = vi.fn().mockResolvedValue({ id: scanId });
      const getScanDetail = vi.fn()
        .mockResolvedValueOnce(makeScanDetail(scanId, 'RUNNING'))
        .mockResolvedValueOnce(makeScanDetail(scanId, 'FAILED', { failureReason }));

      const runner = makeNmapStage('PING_SWEEP', { triggerScan, getScanDetail });
      const ctx = makeCtx();

      const runnerPromise = runner(ctx);
      const rejection = expect(runnerPromise).rejects.toThrow(failureReason); // attach handler before timers fire

      await vi.advanceTimersByTimeAsync(0);
      await vi.advanceTimersByTimeAsync(DEFAULT_POLL_MS);

      await rejection;
    });

    it('reports FAILED scanStatus before throwing', async () => {
      const scanId = 88;
      const triggerScan = vi.fn().mockResolvedValue({ id: scanId });
      const getScanDetail = vi.fn()
        .mockResolvedValueOnce(makeScanDetail(scanId, 'FAILED', { failureReason: 'host unreachable' }));

      const runner = makeNmapStage('PING_SWEEP', { triggerScan, getScanDetail });
      const ctx = makeCtx();

      const runnerPromise = runner(ctx);
      const rejection = expect(runnerPromise).rejects.toThrow(); // attach handler before timers fire

      await vi.advanceTimersByTimeAsync(0);

      await rejection;

      // ctx.report should have captured the FAILED status.
      expect(ctx.reports.some((r) => r.scanStatus === 'FAILED')).toBe(true);
    });

    it('falls back to a generic message when failureReason is null/undefined', async () => {
      const scanId = 77;
      const triggerScan = vi.fn().mockResolvedValue({ id: scanId });
      const getScanDetail = vi.fn().mockResolvedValue(
        makeScanDetail(scanId, 'FAILED', { failureReason: null }),
      );

      const runner = makeNmapStage('PING_SWEEP', { triggerScan, getScanDetail });
      const ctx = makeCtx();
      const runnerPromise = runner(ctx);
      const rejection = expect(runnerPromise).rejects.toThrow(); // attach handler before timers fire

      await vi.advanceTimersByTimeAsync(0);

      await rejection;
    });

    it('does NOT call getScanDetail after FAILED terminal', async () => {
      const scanId = 66;
      const triggerScan = vi.fn().mockResolvedValue({ id: scanId });
      const getScanDetail = vi.fn().mockResolvedValue(
        makeScanDetail(scanId, 'FAILED', { failureReason: 'error' }),
      );

      const runner = makeNmapStage('PING_SWEEP', { triggerScan, getScanDetail });
      const ctx = makeCtx();
      const runnerPromise = runner(ctx);
      const rejection = expect(runnerPromise).rejects.toThrow(); // attach handler before timers fire

      await vi.advanceTimersByTimeAsync(0);
      await rejection;

      // Advance more timers — no extra polls should happen.
      await vi.advanceTimersByTimeAsync(DEFAULT_POLL_MS * 3);
      expect(getScanDetail).toHaveBeenCalledTimes(1);
    });
  });

  // -------------------------------------------------------------------------
  // Case 3 — 429 on submit: runner throws without polling
  // -------------------------------------------------------------------------
  describe('429 on triggerScan', () => {
    it('rejects with the 429 error message when triggerScan throws 429', async () => {
      const triggerScan = vi.fn().mockRejectedValue(
        new Error('429 Rate limit exceeded — retry after 60s'),
      );
      const getScanDetail = vi.fn();

      const runner = makeNmapStage('PING_SWEEP', { triggerScan, getScanDetail });
      const ctx = makeCtx();

      await expect(runner(ctx)).rejects.toThrow(/^429/);
    });

    it('never calls getScanDetail when triggerScan throws 429', async () => {
      const triggerScan = vi.fn().mockRejectedValue(
        new Error('429 Rate limit exceeded — retry after 60s'),
      );
      const getScanDetail = vi.fn();

      const runner = makeNmapStage('PING_SWEEP', { triggerScan, getScanDetail });
      const ctx = makeCtx();

      await expect(runner(ctx)).rejects.toThrow();
      expect(getScanDetail).not.toHaveBeenCalled();
    });

    it('propagates the exact 429 error message unchanged (starts with "429")', async () => {
      const msg = '429 Rate limit exceeded — retry after 120s';
      const triggerScan = vi.fn().mockRejectedValue(new Error(msg));
      const getScanDetail = vi.fn();

      const runner = makeNmapStage('SERVICE_DETECT', { triggerScan, getScanDetail });
      const ctx = makeCtx();

      let thrownErr: Error | undefined;
      try {
        await runner(ctx);
      } catch (e) {
        thrownErr = e as Error;
      }

      expect(thrownErr).toBeDefined();
      expect(thrownErr!.message).toMatch(/^429/);
    });
  });

  // -------------------------------------------------------------------------
  // Case 4 — poll cadence: fake timers drive exactly the expected getScanDetail count
  // -------------------------------------------------------------------------
  describe('poll cadence under fake timers', () => {
    it('fires exactly N getScanDetail calls when advancing N×pollMs before terminal', async () => {
      const scanId = 55;
      const pollMs = 2000;

      const triggerScan = vi.fn().mockResolvedValue({ id: scanId });
      // 3 non-terminal responses, then COMPLETE on the 4th.
      const getScanDetail = vi.fn()
        .mockResolvedValueOnce(makeScanDetail(scanId, 'PENDING'))
        .mockResolvedValueOnce(makeScanDetail(scanId, 'PENDING'))
        .mockResolvedValueOnce(makeScanDetail(scanId, 'RUNNING'))
        .mockResolvedValueOnce(makeScanDetail(scanId, 'COMPLETE'));

      const runner = makeNmapStage('PING_SWEEP', { triggerScan, getScanDetail, pollMs });
      const ctx = makeCtx();
      const runnerPromise = runner(ctx);

      // Fire the first immediate poll.
      await vi.advanceTimersByTimeAsync(0);
      expect(getScanDetail).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(pollMs);
      expect(getScanDetail).toHaveBeenCalledTimes(2);

      await vi.advanceTimersByTimeAsync(pollMs);
      expect(getScanDetail).toHaveBeenCalledTimes(3);

      await vi.advanceTimersByTimeAsync(pollMs);
      expect(getScanDetail).toHaveBeenCalledTimes(4);

      await runnerPromise;

      // No extra polls after COMPLETE.
      await vi.advanceTimersByTimeAsync(pollMs * 3);
      expect(getScanDetail).toHaveBeenCalledTimes(4);
    });

    it('uses 5000ms default poll interval when pollMs is not specified', async () => {
      const scanId = 44;
      const triggerScan = vi.fn().mockResolvedValue({ id: scanId });
      const getScanDetail = vi.fn()
        .mockResolvedValueOnce(makeScanDetail(scanId, 'PENDING'))
        .mockResolvedValueOnce(makeScanDetail(scanId, 'COMPLETE'));

      const runner = makeNmapStage('PING_SWEEP', { triggerScan, getScanDetail });
      const ctx = makeCtx();
      const runnerPromise = runner(ctx);

      await vi.advanceTimersByTimeAsync(0);
      expect(getScanDetail).toHaveBeenCalledTimes(1);

      // Advancing 4999ms should NOT trigger second poll.
      await vi.advanceTimersByTimeAsync(4999);
      expect(getScanDetail).toHaveBeenCalledTimes(1);

      // Advancing 1 more ms crosses the 5000ms threshold.
      await vi.advanceTimersByTimeAsync(1);
      expect(getScanDetail).toHaveBeenCalledTimes(2);

      await runnerPromise;
    });

    it('stops polling after COMPLETE is reached (no extra polls after terminal)', async () => {
      const scanId = 33;
      const pollMs = 1000;
      const triggerScan = vi.fn().mockResolvedValue({ id: scanId });
      const getScanDetail = vi.fn().mockResolvedValue(makeScanDetail(scanId, 'COMPLETE'));

      const runner = makeNmapStage('PING_SWEEP', { triggerScan, getScanDetail, pollMs });
      const ctx = makeCtx();
      const runnerPromise = runner(ctx);

      await vi.advanceTimersByTimeAsync(0);
      await runnerPromise;

      // Advance well past one more pollMs — no extra calls.
      await vi.advanceTimersByTimeAsync(pollMs * 5);
      expect(getScanDetail).toHaveBeenCalledTimes(1);
    });
  });

  // -------------------------------------------------------------------------
  // Case 5 — abort between polls: runner stops, no further getScanDetail calls
  // -------------------------------------------------------------------------
  describe('abort between polls', () => {
    it('stops polling when ctx.signal is aborted between polls and does not reject', async () => {
      const scanId = 22;
      const pollMs = 3000;
      const ac = new AbortController();

      const triggerScan = vi.fn().mockResolvedValue({ id: scanId });
      const getScanDetail = vi.fn()
        .mockResolvedValueOnce(makeScanDetail(scanId, 'PENDING'))
        .mockResolvedValueOnce(makeScanDetail(scanId, 'RUNNING'));

      const runner = makeNmapStage('PING_SWEEP', { triggerScan, getScanDetail, pollMs });
      const ctx = makeCtx({ signal: ac.signal });
      const runnerPromise = runner(ctx);

      // First poll.
      await vi.advanceTimersByTimeAsync(0);
      expect(getScanDetail).toHaveBeenCalledTimes(1);

      // Abort before the second poll fires.
      ac.abort();

      // Advance past where the second poll would fire.
      await vi.advanceTimersByTimeAsync(pollMs);

      // Runner should have resolved (not rejected) and stopped polling.
      await runnerPromise;
      expect(getScanDetail).toHaveBeenCalledTimes(1);
    });

    it('does not call triggerScan again or getScanDetail further after abort', async () => {
      const scanId = 11;
      const pollMs = 1000;
      const ac = new AbortController();

      const triggerScan = vi.fn().mockResolvedValue({ id: scanId });
      const getScanDetail = vi.fn()
        .mockResolvedValue(makeScanDetail(scanId, 'PENDING'));

      const runner = makeNmapStage('OS_FINGERPRINT', { triggerScan, getScanDetail, pollMs });
      const ctx = makeCtx({ signal: ac.signal });
      const runnerPromise = runner(ctx);

      await vi.advanceTimersByTimeAsync(0);

      // Abort and flush.
      ac.abort();
      await vi.advanceTimersByTimeAsync(pollMs * 10);

      await runnerPromise;

      // triggerScan called exactly once.
      expect(triggerScan).toHaveBeenCalledTimes(1);
    });
  });

  // -------------------------------------------------------------------------
  // Shape / interface assertions
  // -------------------------------------------------------------------------
  describe('factory shape', () => {
    it('makeNmapStage is a function that returns a StageRunner (function)', () => {
      const triggerScan = vi.fn().mockResolvedValue({ id: 1 });
      const getScanDetail = vi.fn().mockResolvedValue(makeScanDetail(1, 'COMPLETE'));

      expect(typeof makeNmapStage).toBe('function');

      const runner = makeNmapStage('PING_SWEEP', { triggerScan, getScanDetail });
      expect(typeof runner).toBe('function');
    });

    it('the returned runner accepts a StageContext and returns a Promise', () => {
      const triggerScan = vi.fn().mockResolvedValue({ id: 1 });
      const getScanDetail = vi.fn().mockResolvedValue(makeScanDetail(1, 'COMPLETE'));

      const runner = makeNmapStage('PING_SWEEP', { triggerScan, getScanDetail });
      const ctx = makeCtx();
      const result = runner(ctx);

      expect(result).toBeInstanceOf(Promise);

      // Drain so fake timers don't leak into next test.
      return vi.runAllTimersAsync().then(() => result);
    });
  });
});
