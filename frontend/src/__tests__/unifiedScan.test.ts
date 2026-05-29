/**
 * RED-phase tests for the unified scan stage orchestrator (Task 1.1).
 *
 * Targeted module: frontend/src/lib/unifiedScan.ts (does NOT exist yet — import fails -> RED).
 *
 * Exact exported symbols asserted (from plan-v65.md § "Exact contracts"):
 *   runUnifiedScan
 *   Types: StageId, StageStatus, StageProgress, StageContext, StageRunner,
 *          StageDef, StageState, UnifiedScanProgress, UnifiedScanResult, UnifiedScanDeps
 *
 * All tests use FAKE injected stage runners — NO real network, NO client import.
 * vi.useFakeTimers() controls pacing/concurrency timing deterministically.
 * Drive timers explicitly; do NOT use waitFor under fake timers (deadlocks).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type {
  StageId,
  StageProgress,
  StageContext,
  StageRunner,
  StageDef,
  UnifiedScanProgress,
  UnifiedScanResult,
  UnifiedScanDeps,
} from '../lib/unifiedScan';
import { runUnifiedScan } from '../lib/unifiedScan';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const STAGE_ORDER: StageId[] = [
  'PING_SWEEP',
  'SERVICE_DETECT',
  'OS_FINGERPRINT',
  'OT_ICS_SWEEP',
];

/**
 * Build a StageDef with a synchronously-resolving fake runner (resolves immediately
 * when timers are not needed). The runner calls ctx.report once then resolves.
 */
function makeFakeStage(id: StageId, overrideRunner?: StageRunner): StageDef {
  const run: StageRunner = overrideRunner ?? (async (ctx: StageContext) => {
    ctx.report({});
  });
  return { id, kind: id === 'OT_ICS_SWEEP' ? 'ot' : 'nmap', run };
}

/**
 * Build four fake StageDefs in the canonical stage order.
 * All runners resolve immediately (no timers needed for basic cases).
 */
function makeFourFakeStages(overrides: Partial<Record<StageId, StageRunner>> = {}): StageDef[] {
  return STAGE_ORDER.map((id) =>
    makeFakeStage(id, overrides[id]),
  );
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('runUnifiedScan', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // -------------------------------------------------------------------------
  // Case 1 — all 4 stages dispatched
  // -------------------------------------------------------------------------
  describe('all 4 stages dispatched', () => {
    it('invokes each stage runner exactly once with the provided cidr and resolves with stages.length === 4 in canonical order', async () => {
      const invocations: Array<{ id: StageId; cidr: string }> = [];

      const stages = STAGE_ORDER.map((id): StageDef => ({
        id,
        kind: id === 'OT_ICS_SWEEP' ? 'ot' : 'nmap',
        run: async (ctx: StageContext) => {
          invocations.push({ id, cidr: ctx.cidr });
          ctx.report({});
        },
      }));

      const deps: UnifiedScanDeps = { stages };
      const onProgress = vi.fn();
      const cidr = '10.0.0.0/24';

      const promise = runUnifiedScan(cidr, deps, onProgress);
      await vi.runAllTimersAsync();
      const result: UnifiedScanResult = await promise;

      // Each runner invoked exactly once.
      expect(invocations).toHaveLength(4);
      for (const id of STAGE_ORDER) {
        const calls = invocations.filter((inv) => inv.id === id);
        expect(calls).toHaveLength(1);
        expect(calls[0]!.cidr).toBe(cidr);
      }

      // Result carries 4 stages in canonical order.
      expect(result.stages).toHaveLength(4);
      expect(result.stages.map((s) => s.id)).toEqual(STAGE_ORDER);
    });
  });

  // -------------------------------------------------------------------------
  // Case 2 — per-stage + overall progress
  // -------------------------------------------------------------------------
  describe('per-stage and overall progress', () => {
    it('fires onProgress on status transitions and overall climbs 0 -> 1', async () => {
      // Use a deferred runner so we can observe the pending->running->complete arc.
      // Each runner reports progress then resolves via a setTimeout.
      const resolvers: Array<() => void> = [];

      const stages = STAGE_ORDER.map((id): StageDef => ({
        id,
        kind: id === 'OT_ICS_SWEEP' ? 'ot' : 'nmap',
        run: (ctx: StageContext) =>
          new Promise<void>((resolve) => {
            ctx.report({});
            resolvers.push(() => {
              resolve();
            });
          }),
      }));

      const progressSnapshots: UnifiedScanProgress[] = [];
      const onProgress = (p: UnifiedScanProgress) => {
        progressSnapshots.push({
          stages: p.stages.map((s) => ({ ...s })),
          completedStages: p.completedStages,
          totalStages: p.totalStages,
          overall: p.overall,
        });
      };

      const promise = runUnifiedScan('10.0.0.0/24', { stages }, onProgress);

      // Drain microtasks so runners start.
      await Promise.resolve();
      await Promise.resolve();

      // Resolve all runners.
      for (const resolve of resolvers) {
        resolve();
      }
      await vi.runAllTimersAsync();
      const result: UnifiedScanResult = await promise;

      // completedStages ends at 4.
      expect(result.completedStages).toBe(4);

      // overall must reach 1 in the final snapshot.
      const finalSnap = progressSnapshots[progressSnapshots.length - 1]!;
      expect(finalSnap.overall).toBe(1);

      // totalStages is always 4.
      for (const snap of progressSnapshots) {
        expect(snap.totalStages).toBe(4);
        expect(snap.overall).toBeCloseTo(snap.completedStages / 4);
      }

      // At least 4 progress calls (one per completed stage).
      expect(progressSnapshots.length).toBeGreaterThanOrEqual(4);
    });
  });

  // -------------------------------------------------------------------------
  // Case 3 — per-stage failure isolation (generic error)
  // -------------------------------------------------------------------------
  describe('per-stage failure isolation', () => {
    it('one stage throws Error("boom") -> master RESOLVES; failed stage is failed, others are complete', async () => {
      const failId: StageId = 'SERVICE_DETECT';

      const stages = STAGE_ORDER.map((id): StageDef => ({
        id,
        kind: id === 'OT_ICS_SWEEP' ? 'ot' : 'nmap',
        run: async (ctx: StageContext) => {
          ctx.report({});
          if (id === failId) {
            throw new Error('boom');
          }
        },
      }));

      const onProgress = vi.fn();
      const promise = runUnifiedScan('10.0.0.0/24', { stages }, onProgress);
      await vi.runAllTimersAsync();

      // Master must RESOLVE, not reject.
      const result: UnifiedScanResult = await promise;

      // Failed stage.
      const failedStage = result.stages.find((s) => s.id === failId)!;
      expect(failedStage).toBeDefined();
      expect(failedStage.status).toBe('failed');
      expect(failedStage.error).toBe('boom');

      // Other three complete.
      const otherStages = result.stages.filter((s) => s.id !== failId);
      for (const stage of otherStages) {
        expect(stage.status).toBe('complete');
      }

      // Result tallies.
      expect(result.failedStages).toBe(1);
      expect(result.succeededStages).toBe(3);
      expect(result.completedStages).toBe(4); // completedStages = terminal count (complete + failed)
    });
  });

  // -------------------------------------------------------------------------
  // Case 4 — 429 back-off: stage-local, no global abort
  // -------------------------------------------------------------------------
  describe('429 rate-limit back-off', () => {
    it('one stage throws Error("429 Rate limit exceeded...") -> that stage rateLimited=true; others complete; master resolves', async () => {
      const limitId: StageId = 'PING_SWEEP';

      const stages = STAGE_ORDER.map((id): StageDef => ({
        id,
        kind: id === 'OT_ICS_SWEEP' ? 'ot' : 'nmap',
        run: async (ctx: StageContext) => {
          ctx.report({});
          if (id === limitId) {
            throw new Error('429 Rate limit exceeded — retry after 60s');
          }
        },
      }));

      const onProgress = vi.fn();
      const promise = runUnifiedScan('10.0.0.0/24', { stages }, onProgress);
      await vi.runAllTimersAsync();

      // Master resolves.
      const result: UnifiedScanResult = await promise;

      // Rate-limited stage.
      const rateLimitedStage = result.stages.find((s) => s.id === limitId)!;
      expect(rateLimitedStage).toBeDefined();
      expect(rateLimitedStage.status).toBe('failed');
      expect(rateLimitedStage.rateLimited).toBe(true);

      // Other three stages complete normally.
      const otherStages = result.stages.filter((s) => s.id !== limitId);
      for (const stage of otherStages) {
        expect(stage.status).toBe('complete');
      }

      // No global abort: all 4 stages reached terminal.
      expect(result.completedStages).toBe(4);
      expect(result.failedStages).toBe(1);
      expect(result.succeededStages).toBe(3);
    });
  });

  // -------------------------------------------------------------------------
  // Case 5 — bounded concurrency
  // -------------------------------------------------------------------------
  describe('bounded concurrency', () => {
    it('with concurrency:2 and 4 stages, never more than 2 in-flight simultaneously', async () => {
      let currentInFlight = 0;
      let maxInFlight = 0;

      // Each runner increments in-flight count, waits for a setTimeout, then decrements.
      // The setTimeout makes overlap visible under fake timers.
      const stages = STAGE_ORDER.map((id): StageDef => ({
        id,
        kind: id === 'OT_ICS_SWEEP' ? 'ot' : 'nmap',
        run: (ctx: StageContext) => {
          currentInFlight++;
          if (currentInFlight > maxInFlight) maxInFlight = currentInFlight;
          return new Promise<void>((resolve) => {
            setTimeout(() => {
              currentInFlight--;
              ctx.report({});
              resolve();
            }, 10);
          });
        },
      }));

      const onProgress = vi.fn();
      const promise = runUnifiedScan('10.0.0.0/24', { stages, concurrency: 2 }, onProgress);

      await vi.runAllTimersAsync();
      await promise;

      // Never more than 2 stages in-flight at once.
      expect(maxInFlight).toBeGreaterThan(0);
      expect(maxInFlight).toBeLessThanOrEqual(2);
    });

    it('with default concurrency (4), all 4 stages may be in-flight simultaneously', async () => {
      let maxInFlight = 0;
      let currentInFlight = 0;

      const stages = STAGE_ORDER.map((id): StageDef => ({
        id,
        kind: id === 'OT_ICS_SWEEP' ? 'ot' : 'nmap',
        run: (ctx: StageContext) => {
          currentInFlight++;
          if (currentInFlight > maxInFlight) maxInFlight = currentInFlight;
          return new Promise<void>((resolve) => {
            setTimeout(() => {
              currentInFlight--;
              ctx.report({});
              resolve();
            }, 10);
          });
        },
      }));

      const onProgress = vi.fn();
      // concurrency not specified -> defaults to 4
      const promise = runUnifiedScan('10.0.0.0/24', { stages }, onProgress);

      await vi.runAllTimersAsync();
      await promise;

      // Default concurrency = 4; all 4 stages may be in-flight simultaneously.
      expect(maxInFlight).toBe(4);
    });
  });

  // -------------------------------------------------------------------------
  // Case 6 — abort
  // -------------------------------------------------------------------------
  describe('abort signal', () => {
    it('aborting before timers advance: not-started stages end terminal, in-flight stage sees signal.aborted, master resolves with partial result', async () => {
      const abortController = new AbortController();

      // Track which runners actually started their body.
      const startedIds: StageId[] = [];
      // Track signal state observed by the in-flight stage.
      let signalAbortedObserved: boolean | undefined;

      // With concurrency:1, only one stage can be in-flight at a time.
      // We abort before timers advance — the first stage is in-flight; the rest are queued.
      const stages = STAGE_ORDER.map((id): StageDef => ({
        id,
        kind: id === 'OT_ICS_SWEEP' ? 'ot' : 'nmap',
        run: (ctx: StageContext) => {
          startedIds.push(id);
          ctx.report({});
          return new Promise<void>((resolve) => {
            setTimeout(() => {
              // Check if abort was signalled during our execution.
              signalAbortedObserved = ctx.signal?.aborted;
              resolve();
            }, 50);
          });
        },
      }));

      const onProgress = vi.fn();
      const promise = runUnifiedScan(
        '10.0.0.0/24',
        { stages, concurrency: 1 },
        onProgress,
        abortController.signal,
      );

      // Let the first stage start (drain microtask queue).
      await Promise.resolve();
      await Promise.resolve();

      // Abort before advancing timers.
      abortController.abort();

      // Now advance timers.
      await vi.runAllTimersAsync();

      // Master must resolve (not reject).
      const result: UnifiedScanResult = await promise;
      expect(result).toBeDefined();

      // Result must be partial: not all stages succeeded.
      // Not-started stages end as terminal (failed/aborted) without running their body.
      const terminalCount = result.stages.filter(
        (s) => s.status === 'complete' || s.status === 'failed',
      ).length;
      expect(terminalCount).toBe(4); // all stages reach terminal

      // Queued (not-yet-started) stages must not have run their runner body.
      // With concurrency:1, at most 1 stage started before abort.
      expect(startedIds.length).toBeLessThanOrEqual(2); // generous upper bound; likely 1

      // The queued stages are terminal.
      const notStartedIds = STAGE_ORDER.filter((id) => !startedIds.includes(id));
      for (const id of notStartedIds) {
        const stage = result.stages.find((s) => s.id === id)!;
        expect(stage).toBeDefined();
        expect(stage.status).toBe('failed'); // aborted stages end as failed
      }

      // The in-flight stage's signal was forwarded.
      expect(signalAbortedObserved).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // UnifiedScanResult shape assertions
  // -------------------------------------------------------------------------
  describe('UnifiedScanResult shape', () => {
    it('resolves with correct completedStages, succeededStages, failedStages when all succeed', async () => {
      const stages = makeFourFakeStages();
      const onProgress = vi.fn();
      const promise = runUnifiedScan('10.0.0.0/24', { stages }, onProgress);
      await vi.runAllTimersAsync();
      const result: UnifiedScanResult = await promise;

      expect(result.stages).toHaveLength(4);
      expect(result.completedStages).toBe(4);
      expect(result.succeededStages).toBe(4);
      expect(result.failedStages).toBe(0);
    });

    it('resolves with correct tallies when two stages fail', async () => {
      const failIds: StageId[] = ['PING_SWEEP', 'OS_FINGERPRINT'];

      const stages = STAGE_ORDER.map((id): StageDef => ({
        id,
        kind: id === 'OT_ICS_SWEEP' ? 'ot' : 'nmap',
        run: async (ctx: StageContext) => {
          ctx.report({});
          if (failIds.includes(id)) {
            throw new Error(`${id} failed`);
          }
        },
      }));

      const onProgress = vi.fn();
      const promise = runUnifiedScan('10.0.0.0/24', { stages }, onProgress);
      await vi.runAllTimersAsync();
      const result: UnifiedScanResult = await promise;

      expect(result.completedStages).toBe(4);
      expect(result.failedStages).toBe(2);
      expect(result.succeededStages).toBe(2);
    });
  });

  // -------------------------------------------------------------------------
  // StageState shape
  // -------------------------------------------------------------------------
  describe('StageState shape', () => {
    it('each stage in result has id, kind, and status fields matching the StageDef', async () => {
      const stages = makeFourFakeStages();
      const onProgress = vi.fn();
      const promise = runUnifiedScan('10.0.0.0/24', { stages }, onProgress);
      await vi.runAllTimersAsync();
      const result: UnifiedScanResult = await promise;

      const expectedKinds: Record<StageId, 'nmap' | 'ot'> = {
        PING_SWEEP: 'nmap',
        SERVICE_DETECT: 'nmap',
        OS_FINGERPRINT: 'nmap',
        OT_ICS_SWEEP: 'ot',
      };

      for (const stage of result.stages) {
        expect(stage.id).toBeDefined();
        expect(stage.kind).toBe(expectedKinds[stage.id]);
        expect(stage.status).toBeDefined();
        // All succeed in the happy path.
        expect(stage.status).toBe('complete');
      }
    });

    it('report() folds fine-grained progress into StageState observable via onProgress', async () => {
      const reportedProgress: StageProgress = {
        scanStatus: 'RUNNING',
        discoveredDeviceIds: [1, 2, 3],
      };

      const stages = STAGE_ORDER.map((id): StageDef => ({
        id,
        kind: id === 'OT_ICS_SWEEP' ? 'ot' : 'nmap',
        run: async (ctx: StageContext) => {
          ctx.report(reportedProgress);
        },
      }));

      const progressSnapshots: UnifiedScanProgress[] = [];
      const onProgress = (p: UnifiedScanProgress) => {
        progressSnapshots.push({
          stages: p.stages.map((s) => ({ ...s })),
          completedStages: p.completedStages,
          totalStages: p.totalStages,
          overall: p.overall,
        });
      };

      const promise = runUnifiedScan('10.0.0.0/24', { stages }, onProgress);
      await vi.runAllTimersAsync();
      await promise;

      // At least one snapshot must show the reported scanStatus folded into a StageState.
      const snapsWithScanStatus = progressSnapshots.filter((snap) =>
        snap.stages.some((s) => s.scanStatus === 'RUNNING'),
      );
      expect(snapsWithScanStatus.length).toBeGreaterThan(0);

      // At least one snapshot must show the reported discoveredDeviceIds.
      const snapsWithDevices = progressSnapshots.filter((snap) =>
        snap.stages.some(
          (s) => Array.isArray(s.discoveredDeviceIds) && s.discoveredDeviceIds.length === 3,
        ),
      );
      expect(snapsWithDevices.length).toBeGreaterThan(0);
    });
  });

  // -------------------------------------------------------------------------
  // Stage dependencies (dependsOn) — ordering + cascade
  // -------------------------------------------------------------------------
  describe('stage dependencies (dependsOn)', () => {
    it('a dependent stage does not start until its dependency has completed', async () => {
      const startOrder: StageId[] = [];
      const completeOrder: StageId[] = [];

      // PING_SWEEP takes 10ms; the other three depend on it. With concurrency 4 the dependents
      // would otherwise start immediately — dependsOn must hold them until PING_SWEEP completes.
      const stages: StageDef[] = STAGE_ORDER.map((id) => ({
        id,
        kind: id === 'OT_ICS_SWEEP' ? 'ot' : 'nmap',
        dependsOn: id === 'PING_SWEEP' ? undefined : (['PING_SWEEP'] as StageId[]),
        run: (ctx: StageContext) =>
          new Promise<void>((resolve) => {
            startOrder.push(id);
            setTimeout(() => {
              completeOrder.push(id);
              ctx.report({});
              resolve();
            }, id === 'PING_SWEEP' ? 10 : 1);
          }),
      }));

      const promise = runUnifiedScan('10.0.0.0/24', { stages }, vi.fn());
      // Let microtasks settle: only PING_SWEEP should have started.
      await Promise.resolve();
      await Promise.resolve();
      expect(startOrder).toEqual(['PING_SWEEP']);

      await vi.runAllTimersAsync();
      const result = await promise;

      // PING_SWEEP completes before any dependent starts.
      for (const id of STAGE_ORDER.filter((s) => s !== 'PING_SWEEP')) {
        expect(startOrder.indexOf(id)).toBeGreaterThan(startOrder.indexOf('PING_SWEEP'));
      }
      expect(completeOrder[0]).toBe('PING_SWEEP');
      expect(result.succeededStages).toBe(4);
    });

    it('a failed dependency cascades: dependents are marked failed (skipped) and never run', async () => {
      const ran: StageId[] = [];

      const stages: StageDef[] = STAGE_ORDER.map((id) => ({
        id,
        kind: id === 'OT_ICS_SWEEP' ? 'ot' : 'nmap',
        dependsOn: id === 'PING_SWEEP' ? undefined : (['PING_SWEEP'] as StageId[]),
        run: async (ctx: StageContext) => {
          ran.push(id);
          ctx.report({});
          if (id === 'PING_SWEEP') {
            throw new Error('sweep boom');
          }
        },
      }));

      const promise = runUnifiedScan('10.0.0.0/24', { stages }, vi.fn());
      await vi.runAllTimersAsync();
      const result = await promise;

      // Only PING_SWEEP ever ran its body.
      expect(ran).toEqual(['PING_SWEEP']);

      // PING_SWEEP failed; the three dependents are failed (skipped) — all 4 terminal.
      const ping = result.stages.find((s) => s.id === 'PING_SWEEP')!;
      expect(ping.status).toBe('failed');
      for (const id of STAGE_ORDER.filter((s) => s !== 'PING_SWEEP')) {
        const dep = result.stages.find((s) => s.id === id)!;
        expect(dep.status).toBe('failed');
        expect(dep.error).toMatch(/skipped/i);
      }
      expect(result.completedStages).toBe(4);
      expect(result.failedStages).toBe(4);
      expect(result.succeededStages).toBe(0);
    });
  });
});
