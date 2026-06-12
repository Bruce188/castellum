/**
 * RED-phase tests for the chunked-scan frontend — nmap poll stage chunk
 * propagation.
 *
 * Locked design pinned here:
 *   - ScanDetail (api/types.ts) gains optional `chunksTotal?: number | null`
 *     and `chunksDone?: number | null` (the makeScanDetail extras below are
 *     intentional compile-RED until GREEN adds the fields).
 *   - makeNmapStage's poll loop must propagate `chunksTotal`/`chunksDone`
 *     from the polled ScanDetail into the object it emits via ctx.report
 *     (extending the existing { scanStatus, discoveredDeviceIds } shape).
 *   - SUBMIT payloads are UNCHANGED — deliberately NOT asserted here (the
 *     exact submit-payload pins live in nmapScanStage.test.ts).
 *
 * Harness style mirrors nmapScanStage.test.ts: injected vi.fn() deps, fake
 * timers driven explicitly via vi.advanceTimersByTimeAsync — no waitFor.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ScanDetail } from '../api/types';
import type { StageContext, StageProgress } from '../lib/unifiedScan';
import { makeNmapStage } from '../lib/nmapScanStage';

const DEFAULT_POLL_MS = 5000;

function makeScanDetail(
  id: number,
  status: ScanDetail['status'],
  extra: Partial<ScanDetail> = {},
): ScanDetail {
  return {
    id,
    cidr: '10.20.0.0/16',
    scanType: 'SERVICE_DETECT',
    status,
    requestedAt: '2026-06-12T00:00:00Z',
    completedAt: status === 'COMPLETE' || status === 'FAILED' ? '2026-06-12T00:01:00Z' : null,
    failureReason: null,
    discoveredDeviceIds: [],
    ...extra,
  };
}

function makeCtx(overrides: Partial<StageContext> = {}): StageContext & { reports: StageProgress[] } {
  const reports: StageProgress[] = [];
  return {
    cidr: '10.20.0.0/16',
    report: vi.fn((p: StageProgress) => { reports.push(p); }),
    ...overrides,
    reports,
  };
}

describe('makeNmapStage — chunk progress propagation', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('propagates chunksTotal/chunksDone from the polled detail into every ctx.report emission', async () => {
    const scanId = 7;
    const triggerScan = vi.fn().mockResolvedValue({ id: scanId });
    const getScanDetail = vi.fn()
      // Poll 1 — RUNNING without chunk fields (legacy shape).
      .mockResolvedValueOnce(makeScanDetail(scanId, 'RUNNING'))
      // Poll 2 — RUNNING mid-chunk: 2 of 4 chunks done.
      .mockResolvedValueOnce(makeScanDetail(scanId, 'RUNNING', { chunksTotal: 4, chunksDone: 2 }))
      // Poll 3 — COMPLETE with all chunks done.
      .mockResolvedValueOnce(makeScanDetail(scanId, 'COMPLETE', { chunksTotal: 4, chunksDone: 4 }));

    const runner = makeNmapStage('SERVICE_DETECT', { triggerScan, getScanDetail });
    const ctx = makeCtx();
    const runnerPromise = runner(ctx);

    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(DEFAULT_POLL_MS);
    await vi.advanceTimersByTimeAsync(DEFAULT_POLL_MS);
    await runnerPromise;

    expect(ctx.reports).toHaveLength(3);

    // Guard (current behavior): a detail without chunk fields reports none.
    expect(ctx.reports[0].scanStatus).toBe('RUNNING');
    expect(ctx.reports[0].chunksTotal == null).toBe(true);

    // NEW behavior: the mid-chunk RUNNING report carries both fields onward.
    expect(ctx.reports[1].scanStatus).toBe('RUNNING');
    expect(ctx.reports[1].chunksTotal).toBe(4);
    expect(ctx.reports[1].chunksDone).toBe(2);

    // NEW behavior: the terminal COMPLETE report carries them too.
    expect(ctx.reports[2].scanStatus).toBe('COMPLETE');
    expect(ctx.reports[2].chunksTotal).toBe(4);
    expect(ctx.reports[2].chunksDone).toBe(4);
  });

  it('propagates chunksTotal: 1 unchanged for ordinary single-chunk scans (UI decides rendering)', async () => {
    const scanId = 8;
    const triggerScan = vi.fn().mockResolvedValue({ id: scanId });
    const getScanDetail = vi.fn()
      .mockResolvedValueOnce(makeScanDetail(scanId, 'RUNNING', { chunksTotal: 1, chunksDone: 0 }))
      .mockResolvedValueOnce(makeScanDetail(scanId, 'COMPLETE', { chunksTotal: 1, chunksDone: 1 }));

    const runner = makeNmapStage('SERVICE_DETECT', { triggerScan, getScanDetail });
    const ctx = makeCtx();
    const runnerPromise = runner(ctx);

    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(DEFAULT_POLL_MS);
    await runnerPromise;

    expect(ctx.reports[0].chunksTotal).toBe(1);
    expect(ctx.reports[0].chunksDone).toBe(0);
    expect(ctx.reports[1].chunksTotal).toBe(1);
    expect(ctx.reports[1].chunksDone).toBe(1);
  });
});
