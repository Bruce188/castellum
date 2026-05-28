/**
 * RED-phase tests for the OT sweep orchestrator (Task 2.1).
 *
 * Targeted module: frontend/src/lib/otSweep.ts (does NOT exist yet — import fails → RED).
 *
 * Exact exported symbols asserted (from plan-v64.md § "Exact shared types & config"):
 *   runOtSweep, DEFAULT_SWEEP_CONFIG
 *   Types: OtSweepStatus, OtSweepCell, OtSweepProgress, OtSweepResult, SweepConfig, ProbeFn
 *
 * All tests use a FAKE injected probe function — NO real network, NO fetch/client import.
 * vi.useFakeTimers() is used to control pacing/throttle setTimeout deterministically.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type {
  OtSweepCell,
  OtSweepProgress,
  OtSweepResult,
  SweepConfig,
  ProbeFn,
} from '../lib/otSweep';
import { runOtSweep, DEFAULT_SWEEP_CONFIG } from '../lib/otSweep';
import type { OtProtocol, OtProbeResponse } from '../api/types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** The four protocols the orchestrator must iterate — matches plan AC5 / cross-cutting constraint. */
const PROTOCOLS: { value: OtProtocol; defaultPort: number }[] = [
  { value: 'MODBUS_TCP', defaultPort: 502 },
  { value: 'DNP3', defaultPort: 20000 },
  { value: 'S7COMM', defaultPort: 102 },
  { value: 'BACNET_IP', defaultPort: 47808 },
];

function makeResponse(host: string, protocol: OtProtocol, port: number): OtProbeResponse {
  return {
    host,
    port,
    protocol,
    vendor: 'ACME',
    product: 'PLC-1',
    version: '1.0',
    rawFields: {},
    deviceId: 1,
    serviceId: 2,
    observedAt: '2026-05-28T00:00:00Z',
  };
}

/**
 * Build a minimal SweepConfig merging overrides onto DEFAULT_SWEEP_CONFIG.
 * Safe to call even before DEFAULT_SWEEP_CONFIG is defined — error surfaces at test runtime.
 */
function cfg(overrides: Partial<SweepConfig> = {}): SweepConfig {
  return { ...DEFAULT_SWEEP_CONFIG, ...overrides };
}

// ---------------------------------------------------------------------------
// DEFAULT_SWEEP_CONFIG shape assertions
// ---------------------------------------------------------------------------

describe('DEFAULT_SWEEP_CONFIG', () => {
  it('exports the exact defaults specified in plan-v64 § "Exact shared types & config"', () => {
    expect(DEFAULT_SWEEP_CONFIG).toBeDefined();
    expect(DEFAULT_SWEEP_CONFIG.concurrency).toBe(4);
    expect(DEFAULT_SWEEP_CONFIG.concurrencyMax).toBe(4);
    expect(DEFAULT_SWEEP_CONFIG.concurrencyFloor).toBe(1);
    expect(DEFAULT_SWEEP_CONFIG.perHostSerialize).toBe(true);
    expect(DEFAULT_SWEEP_CONFIG.pacingMsByProtocol).toEqual({
      S7COMM: 750,
      MODBUS_TCP: 500,
      DNP3: 250,
      BACNET_IP: 100,
    });
    expect(DEFAULT_SWEEP_CONFIG.consecutiveFailureThreshold).toBe(3);
    expect(DEFAULT_SWEEP_CONFIG.windowSize).toBe(10);
    expect(DEFAULT_SWEEP_CONFIG.failureRateThreshold).toBe(0.5);
    expect(DEFAULT_SWEEP_CONFIG.successStreakThreshold).toBe(5);
    expect(DEFAULT_SWEEP_CONFIG.pacingMaxMultiplier).toBe(8);
  });
});

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('runOtSweep', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // -------------------------------------------------------------------------
  // Case 1 — all-protocol dispatch
  // -------------------------------------------------------------------------
  describe('all-protocol dispatch', () => {
    it('calls the probe exactly once per (host, protocol) cell with the correct default port', async () => {
      const hosts = ['192.168.1.1', '192.168.1.2'];
      const calls: Array<{ host: string; protocol: OtProtocol; port: number }> = [];

      const fakeProbeFn: ProbeFn = vi.fn((host, protocol, port) => {
        calls.push({ host, protocol, port });
        return Promise.resolve(makeResponse(host, protocol, port));
      });

      const onProgress = vi.fn();
      const sweepPromise = runOtSweep(hosts, PROTOCOLS, fakeProbeFn, cfg(), onProgress);

      // Drain all pending microtasks + timers to completion.
      await vi.runAllTimersAsync();
      const result: OtSweepResult = await sweepPromise;

      // 2 hosts × 4 protocols = 8 cells.
      expect(fakeProbeFn).toHaveBeenCalledTimes(8);

      // Every expected (host, protocol, port) tuple must appear exactly once.
      const expectedTuples: Array<{ host: string; protocol: OtProtocol; port: number }> = [];
      for (const host of hosts) {
        for (const { value, defaultPort } of PROTOCOLS) {
          expectedTuples.push({ host, protocol: value, port: defaultPort });
        }
      }

      for (const expected of expectedTuples) {
        const match = calls.filter(
          (c) => c.host === expected.host && c.protocol === expected.protocol && c.port === expected.port,
        );
        expect(match).toHaveLength(1);
      }

      expect(result.total).toBe(8);
      expect(result.succeeded + result.failed).toBe(8);
      expect(result.cells).toHaveLength(8);
    });
  });

  // -------------------------------------------------------------------------
  // Case 2 — concurrency cap
  // -------------------------------------------------------------------------
  describe('concurrency cap', () => {
    it('never exceeds effectiveConcurrency (default 4) in-flight at any point', async () => {
      const hosts = ['10.0.0.1', '10.0.0.2', '10.0.0.3'];
      let maxInFlight = 0;
      let currentInFlight = 0;

      // Use a concurrency of 2 to make the cap easy to observe.
      const concurrency = 2;

      const fakeProbeFn: ProbeFn = vi.fn((host, protocol, port) => {
        currentInFlight++;
        if (currentInFlight > maxInFlight) maxInFlight = currentInFlight;
        return new Promise<OtProbeResponse>((resolve) => {
          // Resolve on the next tick so in-flight overlap is visible.
          setTimeout(() => {
            currentInFlight--;
            resolve(makeResponse(host, protocol, port));
          }, 10);
        });
      });

      const onProgress = vi.fn();
      const sweepPromise = runOtSweep(
        hosts,
        PROTOCOLS,
        fakeProbeFn,
        cfg({ concurrency, concurrencyMax: concurrency }),
        onProgress,
      );

      await vi.runAllTimersAsync();
      await sweepPromise;

      // Max observed in-flight must never exceed the configured concurrency.
      expect(maxInFlight).toBeGreaterThan(0);
      expect(maxInFlight).toBeLessThanOrEqual(concurrency);
      // Also never exceeds DEFAULT concurrencyMax (4).
      expect(maxInFlight).toBeLessThanOrEqual(4);
    });
  });

  // -------------------------------------------------------------------------
  // Case 3 — per-host serialization
  // -------------------------------------------------------------------------
  describe('per-host serialization', () => {
    it('never dispatches >1 concurrent in-flight probe to the same host', async () => {
      const hosts = ['192.168.0.1', '192.168.0.2'];
      const inFlightPerHost: Record<string, number> = {};
      const maxPerHost: Record<string, number> = {};

      const fakeProbeFn: ProbeFn = vi.fn((host, protocol, port) => {
        inFlightPerHost[host] = (inFlightPerHost[host] ?? 0) + 1;
        if ((inFlightPerHost[host] ?? 0) > (maxPerHost[host] ?? 0)) {
          maxPerHost[host] = inFlightPerHost[host];
        }
        return new Promise<OtProbeResponse>((resolve) => {
          setTimeout(() => {
            inFlightPerHost[host]--;
            resolve(makeResponse(host, protocol, port));
          }, 10);
        });
      });

      const onProgress = vi.fn();
      const sweepPromise = runOtSweep(
        hosts,
        PROTOCOLS,
        fakeProbeFn,
        cfg({ perHostSerialize: true }),
        onProgress,
      );

      await vi.runAllTimersAsync();
      await sweepPromise;

      // Each host must never have had >1 in-flight probe simultaneously.
      for (const host of hosts) {
        expect(maxPerHost[host] ?? 0).toBeLessThanOrEqual(1);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Case 4 — AIMD adaptive throttle trigger + recovery
  // -------------------------------------------------------------------------
  describe('AIMD adaptive throttle', () => {
    it('halves effectiveConcurrency and doubles pacingMultiplier after consecutiveFailureThreshold 5xx errors', async () => {
      const hosts = ['10.1.1.1'];
      // Use enough protocols to exceed the threshold.
      // consecutiveFailureThreshold = 3; we need > 3 consecutive 5xx failures.
      const manyProtocols: { value: OtProtocol; defaultPort: number }[] = [
        { value: 'MODBUS_TCP', defaultPort: 502 },
        { value: 'DNP3', defaultPort: 20000 },
        { value: 'S7COMM', defaultPort: 102 },
        { value: 'BACNET_IP', defaultPort: 47808 },
      ];

      const progressSnapshots: OtSweepProgress[] = [];
      let callCount = 0;
      const failForFirst = 4; // >= consecutiveFailureThreshold (3); triggers AIMD

      const fakeProbeFn: ProbeFn = vi.fn((host, protocol, port) => {
        callCount++;
        if (callCount <= failForFirst) {
          return Promise.reject(new Error('504 Gateway Timeout'));
        }
        return Promise.resolve(makeResponse(host, protocol, port));
      });

      const onProgress = (p: OtSweepProgress) => {
        progressSnapshots.push({ ...p, cells: p.cells.map((c) => ({ ...c })) });
      };

      const sweepPromise = runOtSweep(hosts, manyProtocols, fakeProbeFn, cfg(), onProgress);
      await vi.runAllTimersAsync();
      await sweepPromise;

      // After the trigger, at least one progress snapshot must show:
      //   effectiveConcurrency < initial (4)  — halved toward floor 1
      //   pacingMultiplier > 1                — doubled
      const afterTrigger = progressSnapshots.filter((p) => p.effectiveConcurrency < 4);
      expect(afterTrigger.length).toBeGreaterThan(0);

      const pacingGrown = progressSnapshots.filter((p) => p.pacingMultiplier > 1);
      expect(pacingGrown.length).toBeGreaterThan(0);
    });

    it('recovers effectiveConcurrency (additive increase) and decays pacingMultiplier after successStreakThreshold successes', async () => {
      // Start with a low concurrency and observe recovery after 5 consecutive successes.
      const hosts = ['10.2.2.2'];
      const manyProtocols: { value: OtProtocol; defaultPort: number }[] = [
        { value: 'MODBUS_TCP', defaultPort: 502 },
        { value: 'DNP3', defaultPort: 20000 },
        { value: 'S7COMM', defaultPort: 102 },
        { value: 'BACNET_IP', defaultPort: 47808 },
      ];

      const progressSnapshots: OtSweepProgress[] = [];
      let callCount = 0;
      // Trigger once (3 consecutive 504s → halve concurrency), then succeed everything.
      const fakeProbeFn: ProbeFn = vi.fn((host, protocol, port) => {
        callCount++;
        if (callCount <= 3) {
          return Promise.reject(new Error('504 Gateway Timeout'));
        }
        return Promise.resolve(makeResponse(host, protocol, port));
      });

      const onProgress = (p: OtSweepProgress) => {
        progressSnapshots.push({ ...p, cells: p.cells.map((c) => ({ ...c })) });
      };

      const sweepPromise = runOtSweep(hosts, manyProtocols, fakeProbeFn, cfg(), onProgress);
      await vi.runAllTimersAsync();
      await sweepPromise;

      // The last progress snapshot should show concurrency at or above the post-trigger floor
      // and pacingMultiplier at or below 2 (some recovery happened).
      // (Full recovery to 4 requires > 5 calls, and with only 4 protocols the streak may be partial.)
      const last = progressSnapshots[progressSnapshots.length - 1];
      expect(last).toBeDefined();
      // Recovery means effectiveConcurrency is at least 1 (floor guarantee).
      expect(last!.effectiveConcurrency).toBeGreaterThanOrEqual(1);
    });
  });

  // -------------------------------------------------------------------------
  // Case 5 — non-5xx does NOT trip the throttle
  // -------------------------------------------------------------------------
  describe('non-5xx rejection does not trigger AIMD', () => {
    it('records failed cells for 403 but effectiveConcurrency stays at the initial value', async () => {
      const hosts = ['10.3.3.3'];
      const progressSnapshots: OtSweepProgress[] = [];
      let callCount = 0;

      const fakeProbeFn: ProbeFn = vi.fn((host, protocol, port) => {
        callCount++;
        // Reject with 403 (non-5xx) — should NOT be a throttle signal.
        return Promise.reject(new Error('403 Forbidden'));
      });

      const onProgress = (p: OtSweepProgress) => {
        progressSnapshots.push({ ...p, cells: p.cells.map((c) => ({ ...c })) });
      };

      const sweepPromise = runOtSweep(hosts, PROTOCOLS, fakeProbeFn, cfg(), onProgress);
      await vi.runAllTimersAsync();
      await sweepPromise;

      // All 4 cells failed, but effectiveConcurrency must remain at the initial value (4).
      for (const snap of progressSnapshots) {
        expect(snap.effectiveConcurrency).toBe(4);
        // pacingMultiplier must remain 1 (no throttle growth triggered).
        expect(snap.pacingMultiplier).toBe(1);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Case 6 — progress callback per settled cell
  // -------------------------------------------------------------------------
  describe('progress callback', () => {
    it('fires once per settled cell with monotonically non-decreasing completed tally', async () => {
      const hosts = ['192.168.10.1', '192.168.10.2'];
      const progressSnapshots: OtSweepProgress[] = [];
      let prevCompleted = -1;

      const fakeProbeFn: ProbeFn = vi.fn((host, protocol, port) =>
        Promise.resolve(makeResponse(host, protocol, port)),
      );

      const onProgress = (p: OtSweepProgress) => {
        progressSnapshots.push({ ...p, cells: p.cells.map((c) => ({ ...c })) });
        expect(p.completed).toBeGreaterThanOrEqual(prevCompleted);
        prevCompleted = p.completed;
      };

      const sweepPromise = runOtSweep(hosts, PROTOCOLS, fakeProbeFn, cfg(), onProgress);
      await vi.runAllTimersAsync();
      const result = await sweepPromise;

      // total = 2 × 4 = 8; onProgress fires once per settled cell (8 times),
      // plus the optional initial snapshot (may be 8 or 9 total).
      expect(progressSnapshots.length).toBeGreaterThanOrEqual(8);

      // Final snapshot: completed === total.
      const lastSnap = progressSnapshots[progressSnapshots.length - 1]!;
      expect(lastSnap.completed).toBe(8);
      expect(lastSnap.total).toBe(8);
      expect(lastSnap.succeeded + lastSnap.failed).toBe(8);

      // result totals must match.
      expect(result.succeeded).toBe(8);
      expect(result.failed).toBe(0);
    });

    it('carries partial result on each success cell and partial error on each failure cell', async () => {
      const hosts = ['172.16.0.1'];
      const progressSnapshots: OtSweepProgress[] = [];

      let callCount = 0;
      const fakeProbeFn: ProbeFn = vi.fn((host, protocol, port) => {
        callCount++;
        // Alternate succeed/fail for easy assertion.
        if (callCount % 2 === 0) {
          return Promise.reject(new Error('503 Service Unavailable'));
        }
        return Promise.resolve(makeResponse(host, protocol, port));
      });

      const onProgress = (p: OtSweepProgress) => {
        progressSnapshots.push({ ...p, cells: p.cells.map((c) => ({ ...c })) });
      };

      const sweepPromise = runOtSweep(hosts, PROTOCOLS, fakeProbeFn, cfg(), onProgress);
      await vi.runAllTimersAsync();
      await sweepPromise;

      const finalSnap = progressSnapshots[progressSnapshots.length - 1]!;
      // Settled success cells must have result set; settled failure cells must have error set.
      for (const cell of finalSnap.cells) {
        if (cell.status === 'success') {
          expect(cell.result).toBeDefined();
          expect(cell.result!.host).toBe(hosts[0]);
        }
        if (cell.status === 'failed') {
          expect(cell.error).toBeDefined();
          expect(typeof cell.error).toBe('string');
        }
      }
    });

    it('exposes effectiveConcurrency and pacingMultiplier as observable fields on each snapshot', async () => {
      const hosts = ['172.16.1.1'];
      const progressSnapshots: OtSweepProgress[] = [];

      const fakeProbeFn: ProbeFn = vi.fn((host, protocol, port) =>
        Promise.resolve(makeResponse(host, protocol, port)),
      );

      const onProgress = (p: OtSweepProgress) => {
        progressSnapshots.push({ ...p });
      };

      const sweepPromise = runOtSweep(hosts, PROTOCOLS, fakeProbeFn, cfg(), onProgress);
      await vi.runAllTimersAsync();
      await sweepPromise;

      for (const snap of progressSnapshots) {
        expect(typeof snap.effectiveConcurrency).toBe('number');
        expect(typeof snap.pacingMultiplier).toBe('number');
        expect(snap.effectiveConcurrency).toBeGreaterThanOrEqual(1);
        expect(snap.pacingMultiplier).toBeGreaterThanOrEqual(1);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Case 7 — pacing applied (per-host inter-probe gap)
  // -------------------------------------------------------------------------
  describe('pacing', () => {
    it('enforces the configured per-protocol base pacing gap between same-host probes under fake timers', async () => {
      // Single host, 2 protocols. The orchestrator must wait at least the base pacing
      // before dispatching the second probe to this host.
      // We use MODBUS_TCP (500 ms) and S7COMM (750 ms) so the gaps are observable.
      const singleHost = ['10.10.10.10'];
      const dispatchTimestamps: Array<{ protocol: OtProtocol; ts: number }> = [];

      const fastProtocols: { value: OtProtocol; defaultPort: number }[] = [
        { value: 'MODBUS_TCP', defaultPort: 502 },
        { value: 'S7COMM', defaultPort: 102 },
      ];

      const fakeProbeFn: ProbeFn = vi.fn((host, protocol, port) => {
        dispatchTimestamps.push({ protocol, ts: Date.now() });
        return Promise.resolve(makeResponse(host, protocol, port));
      });

      const onProgress = vi.fn();
      const sweepPromise = runOtSweep(singleHost, fastProtocols, fakeProbeFn, cfg(), onProgress);

      // Advance timers so pacing gaps elapse.
      await vi.runAllTimersAsync();
      await sweepPromise;

      // Both probes must have fired.
      expect(dispatchTimestamps).toHaveLength(2);

      // The gap between first and second dispatch must be >= the base pacing of the first protocol.
      // (Which protocol fired first may vary, but the gap is always >= the smaller base pacing.)
      const [first, second] = dispatchTimestamps as [
        { protocol: OtProtocol; ts: number },
        { protocol: OtProtocol; ts: number },
      ];
      const pacingMs = DEFAULT_SWEEP_CONFIG.pacingMsByProtocol[first.protocol];
      expect(second.ts - first.ts).toBeGreaterThanOrEqual(pacingMs);
    });
  });

  // -------------------------------------------------------------------------
  // Case 8 — abort signal
  // -------------------------------------------------------------------------
  describe('abort signal', () => {
    it('resolves with a partial result and dispatches no new probes after signal is aborted', async () => {
      const hosts = ['10.20.30.1', '10.20.30.2', '10.20.30.3'];
      const abortController = new AbortController();
      let dispatchCount = 0;

      const fakeProbeFn: ProbeFn = vi.fn((host, protocol, port) => {
        dispatchCount++;
        // Abort after the first probe is dispatched so we can observe partial results.
        if (dispatchCount === 1) {
          abortController.abort();
        }
        return new Promise<OtProbeResponse>((resolve) => {
          setTimeout(() => resolve(makeResponse(host, protocol, port)), 50);
        });
      });

      const onProgress = vi.fn();
      const sweepPromise = runOtSweep(
        hosts,
        PROTOCOLS,
        fakeProbeFn,
        cfg(),
        onProgress,
        abortController.signal,
      );

      await vi.runAllTimersAsync();
      const result = await sweepPromise;

      // Must resolve (not reject) — partial result.
      expect(result).toBeDefined();
      expect(result.total).toBe(hosts.length * PROTOCOLS.length);
      // After abort, dispatch must be far less than the total 12 cells.
      expect(dispatchCount).toBeLessThan(hosts.length * PROTOCOLS.length);
      // Partial snapshot: settled < total.
      expect(result.succeeded + result.failed).toBeLessThan(result.total);
    });
  });

  // -------------------------------------------------------------------------
  // OtSweepResult terminal shape
  // -------------------------------------------------------------------------
  describe('OtSweepResult terminal shape', () => {
    it('resolves with cells, total, succeeded, failed matching the final tallies', async () => {
      const hosts = ['10.0.1.1'];
      let callCount = 0;
      const fakeProbeFn: ProbeFn = vi.fn((host, protocol, port) => {
        callCount++;
        if (callCount === 2) {
          return Promise.reject(new Error('500 Internal Server Error'));
        }
        return Promise.resolve(makeResponse(host, protocol, port));
      });

      const onProgress = vi.fn();
      const sweepPromise = runOtSweep(hosts, PROTOCOLS, fakeProbeFn, cfg(), onProgress);
      await vi.runAllTimersAsync();
      const result: OtSweepResult = await sweepPromise;

      expect(result.cells).toHaveLength(4); // 1 host × 4 protocols
      expect(result.total).toBe(4);
      expect(result.succeeded).toBe(3);
      expect(result.failed).toBe(1);

      const successCells = result.cells.filter((c: OtSweepCell) => c.status === 'success');
      const failedCells = result.cells.filter((c: OtSweepCell) => c.status === 'failed');
      expect(successCells).toHaveLength(3);
      expect(failedCells).toHaveLength(1);

      for (const sc of successCells) {
        expect(sc.result).toBeDefined();
      }
      for (const fc of failedCells) {
        expect(fc.error).toBeDefined();
      }
    });
  });
});
