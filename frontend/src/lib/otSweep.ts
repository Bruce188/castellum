/**
 * OT sweep orchestrator — pure-TS, no React, no direct network.
 * The probe function is injected for full testability under fake timers.
 */

import type { OtProtocol, OtProbeResponse } from '../api/types';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type OtSweepStatus = 'pending' | 'in-flight' | 'success' | 'failed';

export interface OtSweepCell {
  host: string;
  protocol: OtProtocol;
  port: number;
  status: OtSweepStatus;
  result?: OtProbeResponse;
  error?: string;
}

export interface OtSweepProgress {
  cells: OtSweepCell[];
  total: number;
  completed: number;
  succeeded: number;
  failed: number;
  inFlight: number;
  effectiveConcurrency: number;
  pacingMultiplier: number;
}

export interface OtSweepResult {
  cells: OtSweepCell[];
  total: number;
  succeeded: number;
  failed: number;
}

export interface SweepConfig {
  concurrency: number;
  concurrencyMax: number;
  concurrencyFloor: number;
  perHostSerialize: boolean;
  pacingMsByProtocol: Record<OtProtocol, number>;
  consecutiveFailureThreshold: number;
  windowSize: number;
  failureRateThreshold: number;
  successStreakThreshold: number;
  pacingMaxMultiplier: number;
}

export type ProbeFn = (
  host: string,
  protocol: OtProtocol,
  port: number,
  signal?: AbortSignal,
) => Promise<OtProbeResponse>;

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

export const DEFAULT_SWEEP_CONFIG: SweepConfig = {
  concurrency: 4,
  concurrencyMax: 4,
  concurrencyFloor: 1,
  perHostSerialize: true,
  pacingMsByProtocol: {
    S7COMM: 750,
    MODBUS_TCP: 500,
    DNP3: 250,
    BACNET_IP: 100,
  },
  consecutiveFailureThreshold: 3,
  windowSize: 10,
  failureRateThreshold: 0.5,
  successStreakThreshold: 5,
  pacingMaxMultiplier: 8,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * A 5xx or network error is a throttle signal (load on the remote end).
 * Non-5xx errors (403, 404, 400…) represent application-level failures — NOT load.
 */
function isThrottleSignal(err: unknown): boolean {
  if (err instanceof TypeError) {
    // Network-level error (fetch failed, connection refused, etc.)
    return true;
  }
  if (err instanceof Error) {
    return /^5\d\d\b/.test(err.message.trim());
  }
  return false;
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

export async function runOtSweep(
  hosts: string[],
  protocols: { value: OtProtocol; defaultPort: number }[],
  probe: ProbeFn,
  config: SweepConfig,
  onProgress: (p: OtSweepProgress) => void,
  signal?: AbortSignal,
): Promise<OtSweepResult> {
  const total = hosts.length * protocols.length;

  // Build the full cell matrix (hosts × protocols).
  const cells: OtSweepCell[] = [];
  for (const host of hosts) {
    for (const { value, defaultPort } of protocols) {
      cells.push({ host, protocol: value, port: defaultPort, status: 'pending' });
    }
  }

  // AIMD state
  let effectiveConcurrency = config.concurrency;
  let pacingMultiplier = 1;
  let consecutiveFailures = 0;
  let consecutiveSuccesses = 0;
  const outcomeWindow: boolean[] = []; // true = success, false = throttle failure

  // Tracking
  let inFlightCount = 0;
  let succeeded = 0;
  let failed = 0;

  // Per-host serialization: last-promise for each host so we chain probes sequentially.
  const hostLastPromise: Map<string, Promise<void>> = new Map();

  function snapshot(): OtSweepProgress {
    return {
      cells: cells.map((c) => ({ ...c })),
      total,
      completed: succeeded + failed,
      succeeded,
      failed,
      inFlight: inFlightCount,
      effectiveConcurrency,
      pacingMultiplier,
    };
  }

  function recordOutcome(isThrottle: boolean): void {
    // Sliding window update
    outcomeWindow.push(!isThrottle); // true = success outcome for window
    if (outcomeWindow.length > config.windowSize) {
      outcomeWindow.shift();
    }

    if (isThrottle) {
      consecutiveFailures++;
      consecutiveSuccesses = 0;

      const failureRate =
        outcomeWindow.length > 0
          ? outcomeWindow.filter((v) => !v).length / outcomeWindow.length
          : 0;

      const shouldThrottle =
        consecutiveFailures >= config.consecutiveFailureThreshold ||
        failureRate > config.failureRateThreshold;

      if (shouldThrottle) {
        effectiveConcurrency = Math.max(
          config.concurrencyFloor,
          Math.floor(effectiveConcurrency / 2),
        );
        pacingMultiplier = Math.min(config.pacingMaxMultiplier, pacingMultiplier * 2);
        consecutiveFailures = 0;
      }
    } else {
      consecutiveFailures = 0;
      consecutiveSuccesses++;

      if (consecutiveSuccesses >= config.successStreakThreshold) {
        effectiveConcurrency = Math.min(config.concurrencyMax, effectiveConcurrency + 1);
        pacingMultiplier = Math.max(1, pacingMultiplier / 2);
        consecutiveSuccesses = 0;
      }
    }
  }

  // Pool: a Set of in-flight "slot" promises. We use a simple counter approach
  // with a polling mechanism driven by Promise resolution.
  //
  // Strategy: iterate cells in order; for each cell, wait until inFlightCount < effectiveConcurrency
  // and (if perHostSerialize) the host's slot is free, then dispatch.
  //
  // Because fake timers drive setTimeout, we use Promise.resolve() microtask yields to
  // avoid busy-waiting while still allowing the event loop to process.

  // We track completion via a resolving promise per cell.
  // We'll drive the pool with an async loop that dispatches cells one at a time,
  // waiting for a slot to open before dispatching each next cell.
  // "Waiting for a slot" = awaiting a Promise that resolves when inFlightCount drops below limit.

  // We maintain a set of release callbacks that are called when any in-flight probe settles.
  type Releaser = () => void;
  const slotReleasers: Set<Releaser> = new Set();

  function waitForSlot(): Promise<void> {
    // Already have a slot available right now?
    if (inFlightCount < effectiveConcurrency) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      slotReleasers.add(resolve);
    });
  }

  function notifySlotReleasers(): void {
    // Wake up waiters — they'll re-check the condition.
    const toNotify = [...slotReleasers];
    slotReleasers.clear();
    for (const r of toNotify) r();
  }

  // Per-host serialization: we chain each host's probes so only one runs at a time.
  // After the pacing delay, we invoke the probe. The chain is: prevChain -> pace -> probe.
  // We separate the "pacing + probe" from the global pool slot so that pacing time
  // does NOT consume a global pool slot — only the actual probe call does.

  // Actually, to honour both constraints simultaneously:
  // 1. Global pool: never more than effectiveConcurrency probes in flight.
  // 2. Per-host: never more than 1 probe per host in flight.
  //
  // Approach: the per-host chain gates dispatch; the global pool gates concurrency.
  // We acquire the global slot BEFORE dispatching (inside the chain), and release AFTER settle.

  // Per-host "last dispatch" promise: resolves when the previous host probe (including pacing) is done.
  // We chain: hostLastPromise[host] = hostLastPromise[host].then(() => pace).then(() => probeAndRecord)

  // We track the overall completion via a counter and a master deferred.
  let totalSettled = 0;
  let masterResolve!: (r: OtSweepResult) => void;
  const masterPromise = new Promise<OtSweepResult>((res) => {
    masterResolve = res;
  });

  function maybeResolve(): void {
    if (totalSettled === total) {
      masterResolve({
        cells: cells.map((c) => ({ ...c })),
        total,
        succeeded,
        failed,
      });
    }
  }

  async function dispatchCell(cell: OtSweepCell): Promise<void> {
    const paceMs = config.pacingMsByProtocol[cell.protocol] * pacingMultiplier;

    // Wait for pacing gap (host-serialization chain already ensures we only run
    // this after the previous host probe settled).
    if (paceMs > 0) {
      await delay(paceMs);
    }

    // Check abort before claiming a global slot.
    if (signal?.aborted) {
      // Mark pending cells as failed (skipped), not dispatched.
      // We do NOT dispatch; just let this resolve so the chain unblocks.
      return;
    }

    // Wait for a global pool slot.
    while (inFlightCount >= effectiveConcurrency) {
      await waitForSlot();
      // After being woken, re-check abort.
      if (signal?.aborted) {
        return;
      }
    }

    // Double-check abort after potentially waiting.
    if (signal?.aborted) {
      return;
    }

    // Claim the slot.
    inFlightCount++;
    cell.status = 'in-flight';

    try {
      const result = await probe(cell.host, cell.protocol, cell.port, signal);
      cell.status = 'success';
      cell.result = result;
      succeeded++;
      recordOutcome(false);
    } catch (err) {
      cell.status = 'failed';
      cell.error = err instanceof Error ? err.message : String(err);
      failed++;
      recordOutcome(isThrottleSignal(err));
    } finally {
      inFlightCount--;
      totalSettled++;
      notifySlotReleasers();
      onProgress(snapshot());
      maybeResolve();
    }
  }

  // Build per-host dispatch chains.
  for (const cell of cells) {
    const host = cell.host;
    const prevChain = hostLastPromise.get(host) ?? Promise.resolve();

    if (config.perHostSerialize) {
      // Chain: wait for previous host probe to fully complete (including its settle),
      // THEN do pacing + probe for this cell.
      const nextChain = prevChain.then(() => dispatchCell(cell));
      hostLastPromise.set(host, nextChain);
    } else {
      // No per-host serialization: just dispatch with pool-only gating.
      dispatchCell(cell);
    }
  }

  // Handle abort: if signal fires and there are still pending cells that will never
  // settle (because we skip dispatching aborted cells), we need to resolve.
  if (signal) {
    signal.addEventListener('abort', () => {
      // Cells that are still 'pending' or 'in-flight' won't settle via normal path once aborted.
      // In-flight cells will still settle (their probe is running).
      // Pending cells that haven't been dispatched yet will be skipped in dispatchCell().
      // We need to ensure masterResolve fires eventually.
      // We do this by periodically checking after abort, but since we're under fake timers,
      // we rely on the chain callbacks to eventually call maybeResolve when all dispatched
      // probes settle. Pending skipped cells won't increment totalSettled.
      // We resolve immediately with partial results.
      masterResolve({
        cells: cells.map((c) => ({ ...c })),
        total,
        succeeded,
        failed,
      });
    });
  }

  return masterPromise;
}
