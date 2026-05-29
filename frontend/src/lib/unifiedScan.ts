/**
 * Pure-TS bounded stage orchestrator for unified network scan.
 * No React, no fetch/client imports — stage runners are injected via deps.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type StageId =
  | 'PING_SWEEP'
  | 'SERVICE_DETECT'
  | 'OS_FINGERPRINT'
  | 'OT_ICS_SWEEP'
  | 'DOCKER_DISCOVERY';

export type StageStatus = 'pending' | 'running' | 'complete' | 'failed';

export interface StageProgress {
  scanStatus?: string;
  discoveredDeviceIds?: number[];
  otCompleted?: number;
  otTotal?: number;
}

export interface StageContext {
  cidr: string;
  signal?: AbortSignal;
  report: (p: StageProgress) => void;
}

export type StageRunner = (ctx: StageContext) => Promise<void>;

export interface StageDef {
  id: StageId;
  kind: 'nmap' | 'ot' | 'docker';
  run: StageRunner;
  /**
   * Stage ids that must reach a successful `complete` status before this stage may start.
   * A dependency that ends `failed` cascades: the dependent stage is marked `failed` with a
   * "skipped — <dep> did not complete" error rather than running (and rather than hanging).
   * Omitted/empty means the stage has no prerequisites and may dispatch immediately.
   */
  dependsOn?: StageId[];
}

export interface StageState {
  id: StageId;
  kind: 'nmap' | 'ot' | 'docker';
  status: StageStatus;
  scanStatus?: string;
  discoveredDeviceIds?: number[];
  otCompleted?: number;
  otTotal?: number;
  error?: string;
  rateLimited?: boolean;
}

export interface UnifiedScanProgress {
  stages: StageState[];
  completedStages: number;
  totalStages: number;
  overall: number;
}

export interface UnifiedScanResult {
  stages: StageState[];
  completedStages: number;
  succeededStages: number;
  failedStages: number;
}

export interface UnifiedScanDeps {
  stages: StageDef[];
  concurrency?: number;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export function runUnifiedScan(
  cidr: string,
  deps: UnifiedScanDeps,
  onProgress: (p: UnifiedScanProgress) => void,
  signal?: AbortSignal,
): Promise<UnifiedScanResult> {
  const concurrency = deps.concurrency ?? 4;

  // Initialize stage states in the order provided by deps.stages.
  const stateMap = new Map<StageId, StageState>();
  const orderedIds: StageId[] = [];

  for (const def of deps.stages) {
    orderedIds.push(def.id);
    stateMap.set(def.id, {
      id: def.id,
      kind: def.kind,
      status: 'pending',
    });
  }

  // Total stages is the count actually supplied — keeps the progress denominator correct
  // as stages are added (e.g. DOCKER_DISCOVERY) rather than hard-coding a fixed count.
  const totalStages = orderedIds.length;

  // Helper: build a snapshot of current progress.
  function buildProgress(): UnifiedScanProgress {
    const stages = orderedIds.map((id) => ({ ...stateMap.get(id)! }));
    const completedStages = stages.filter(
      (s) => s.status === 'complete' || s.status === 'failed',
    ).length;
    return {
      stages,
      completedStages,
      totalStages,
      overall: completedStages / totalStages,
    };
  }

  // Helper: update a stage state and fire onProgress.
  function updateState(id: StageId, patch: Partial<StageState>): void {
    const current = stateMap.get(id)!;
    stateMap.set(id, { ...current, ...patch });
    onProgress(buildProgress());
  }

  return new Promise<UnifiedScanResult>((resolve) => {
    const stageQueue: StageDef[] = [...deps.stages];
    let inFlight = 0;
    let settled = 0;

    // Dependency helpers ----------------------------------------------------
    // A stage is "ready" when every dependency has reached terminal `complete`.
    // A stage is "blocked-failed" when any dependency ended `failed` — it can never
    // become ready, so we settle it immediately (cascade) instead of leaving it queued.
    function depStatuses(def: StageDef): StageStatus[] {
      return (def.dependsOn ?? []).map((depId) => stateMap.get(depId)?.status ?? 'pending');
    }
    function depsSatisfied(def: StageDef): boolean {
      return depStatuses(def).every((s) => s === 'complete');
    }
    function anyDepFailed(def: StageDef): boolean {
      return depStatuses(def).some((s) => s === 'failed');
    }
    function failedDepName(def: StageDef): StageId | undefined {
      return (def.dependsOn ?? []).find((depId) => stateMap.get(depId)?.status === 'failed');
    }

    function tryDispatch(): void {
      // Dispatch stages while we have capacity and queue entries.
      while (inFlight < concurrency && stageQueue.length > 0) {
        // Check abort before starting a new stage.
        if (signal?.aborted) {
          // Mark all remaining queued stages as failed (not started).
          while (stageQueue.length > 0) {
            const def = stageQueue.shift()!;
            updateState(def.id, { status: 'failed', error: 'aborted' });
            settled++;
          }
          checkDone();
          return;
        }

        // First, drain any queued stage whose dependency has already failed — cascade it
        // to failed without running. This keeps the queue from deadlocking on a dep that
        // will never complete and surfaces the cause in the UI.
        const failedIdx = stageQueue.findIndex((d) => anyDepFailed(d));
        if (failedIdx !== -1) {
          const [blocked] = stageQueue.splice(failedIdx, 1);
          const depName = failedDepName(blocked);
          updateState(blocked.id, {
            status: 'failed',
            error: `skipped — ${depName ?? 'dependency'} did not complete`,
          });
          settled++;
          continue;
        }

        // Find the first queued stage whose dependencies are all complete.
        const readyIdx = stageQueue.findIndex((d) => depsSatisfied(d));
        if (readyIdx === -1) {
          // Nothing is dispatchable right now: remaining stages are waiting on deps that are
          // still pending/running. A later settle of those deps re-invokes tryDispatch().
          return;
        }

        const [def] = stageQueue.splice(readyIdx, 1);
        inFlight++;

        // Transition to running.
        updateState(def.id, { status: 'running' });

        const ctx: StageContext = {
          cidr,
          signal,
          report: (p: StageProgress) => {
            // Fold fine-grained progress into the stage state and re-emit.
            const current = stateMap.get(def.id)!;
            stateMap.set(def.id, { ...current, ...p });
            onProgress(buildProgress());
          },
        };

        def.run(ctx).then(
          () => {
            // Stage completed successfully.
            inFlight--;
            settled++;
            updateState(def.id, { status: 'complete' });
            tryDispatch();
            checkDone();
          },
          (err: unknown) => {
            // Stage failed — isolate, do not abort siblings.
            inFlight--;
            settled++;
            const message = err instanceof Error ? err.message : String(err);
            const patch: Partial<StageState> = {
              status: 'failed',
              error: message,
            };
            if (message.startsWith('429')) {
              patch.rateLimited = true;
            }
            updateState(def.id, patch);
            tryDispatch();
            checkDone();
          },
        );
      }
    }

    function checkDone(): void {
      // All stages are terminal when settled === totalStages.
      const allTerminal =
        settled === orderedIds.length && stageQueue.length === 0 && inFlight === 0;
      if (!allTerminal) return;

      const stages = orderedIds.map((id) => ({ ...stateMap.get(id)! }));
      const completedStages = stages.filter(
        (s) => s.status === 'complete' || s.status === 'failed',
      ).length;
      const succeededStages = stages.filter((s) => s.status === 'complete').length;
      const failedStages = stages.filter((s) => s.status === 'failed').length;

      resolve({
        stages,
        completedStages,
        succeededStages,
        failedStages,
      });
    }

    // Handle the case where signal is already aborted before we start.
    if (signal?.aborted) {
      for (const def of stageQueue.splice(0)) {
        updateState(def.id, { status: 'failed', error: 'aborted' });
        settled++;
      }
      checkDone();
      return;
    }

    // Listen for abort while stages are in-flight.
    if (signal) {
      signal.addEventListener('abort', () => {
        // Mark queued (not-yet-started) stages as failed immediately.
        while (stageQueue.length > 0) {
          const def = stageQueue.shift()!;
          updateState(def.id, { status: 'failed', error: 'aborted' });
          settled++;
        }
        // In-flight stages will complete naturally (their ctx.signal is forwarded).
        checkDone();
      });
    }

    tryDispatch();
  });
}
