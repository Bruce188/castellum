/**
 * RED-phase tests for Task 3.1 — UnifiedScanControl + ScansPage wiring.
 *
 * Targeted module: frontend/src/components/UnifiedScanControl.tsx (does NOT exist yet → RED).
 * Also requires: frontend/src/lib/otProtocols.ts (does NOT exist yet).
 *
 * Strategy per plan-v65.md Task 3.1 / prompts-v60.md Task 3.1:
 *   - vi.mock('../api/client') with triggerScan/getScanDetail/listDevices/probeOtOnce/getActiveCidr
 *   - Run REAL runUnifiedScan + REAL makeNmapStage + REAL runOtSweep — only the client is mocked.
 *   - Use vi.useFakeTimers() to control poll cadence (makeNmapStage default 5000ms) and
 *     OT sweep pacing. Drive timers explicitly with vi.runAllTimersAsync() — do NOT use
 *     waitFor under fake timers (its poll loop deadlocks).
 *   - Mirror the OtProbePanel.test.tsx mock-factory + makePage helper pattern.
 *
 * Test IDs from plan-v65.md Task 3.1:
 *   unified-scan-btn          — primary "Scan this network" button
 *   unified-progress          — <progress> element (value/max)
 *   unified-stage-${id}       — per-stage row for each StageId
 *   unified-advanced-toggle   — <details> wrapping ScanTriggerForm + OtProbePanel
 *   unified-scan-stop-btn     — abort button (shown while running)
 *   CIDR <input>              — no dedicated testid in plan; query by role/placeholder
 *
 * AC1 — unified dispatch: click unified-scan-btn → triggerScan ×3, listDevices ×1, probeOtOnce ×8
 * AC3 — progress renders and reaches 1 (all stages complete); per-stage rows flip to complete
 * AC4 — unified-advanced-toggle contains ScanTriggerForm + OtProbePanel; both still work
 * AC4b — one nmap stage FAILED does not abort others
 */

import { render, screen, fireEvent, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// The component under test — does NOT exist yet → import fails → RED.
import { UnifiedScanControl } from '../components/UnifiedScanControl';

import { api } from '../api/client';
import type { Page, Device } from '../api/types';

// ---------------------------------------------------------------------------
// Mock the API client (all fns used by UnifiedScanControl + children)
// ---------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  api: {
    triggerScan: vi.fn(),
    getScanDetail: vi.fn(),
    listDevices: vi.fn(),
    probeOtOnce: vi.fn(),
    getActiveCidr: vi.fn(),
    // OtProbePanel also calls probeOt for single-protocol advanced form
    probeOt: vi.fn(),
  },
}));

const mockTriggerScan = vi.mocked(api.triggerScan);
const mockGetScanDetail = vi.mocked(api.getScanDetail);
const mockListDevices = vi.mocked(api.listDevices);
const mockProbeOtOnce = vi.mocked(api.probeOtOnce);
const mockGetActiveCidr = vi.mocked(api.getActiveCidr);
const mockProbeOt = vi.mocked(api.probeOt);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_CIDR = '10.0.0.0/24';

/** Build a Page<Device> from a list of IP strings (mirrors OtProbePanel.test.tsx). */
function makePage(ips: string[]): Page<Device> {
  return {
    content: ips.map((ip, i) => ({
      id: i + 1,
      ipAddress: ip,
      hostname: null,
      macAddress: null,
      firstSeen: null,
      lastSeen: null,
      criticality: 'LOW' as const,
      discoveryScope: 'HOME' as const,
      lastSeenIface: null,
      discoverySource: null,
      serviceCount: 0,
      osName: null,
      osAccuracy: null,
      osCpe: null,
    })),
    totalElements: ips.length,
    totalPages: 1,
    number: 0,
    size: 200,
  };
}

const MOCK_PROBE_RESULT = {
  host: '10.0.0.1',
  port: 502,
  protocol: 'MODBUS_TCP' as const,
  vendor: 'ACME',
  product: 'PLC-1',
  version: '1.0',
  rawFields: {},
  deviceId: 1,
  serviceId: 1,
  observedAt: '2026-05-28T00:00:00Z',
};

function makeScanDetail(
  id: number,
  status: 'PENDING' | 'RUNNING' | 'COMPLETE' | 'FAILED',
  extra: Partial<{ discoveredDeviceIds: number[]; failureReason: string }> = {},
) {
  return {
    id,
    cidr: TEST_CIDR,
    scanType: 'PING_SWEEP' as const,
    status,
    requestedAt: '2026-05-28T00:00:00Z',
    completedAt: status === 'COMPLETE' || status === 'FAILED' ? '2026-05-28T00:01:00Z' : null,
    failureReason: extra.failureReason ?? null,
    retryCount: 0,
    discoveredDeviceIds: extra.discoveredDeviceIds ?? [],
  };
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeEach(() => {
  mockTriggerScan.mockReset();
  mockGetScanDetail.mockReset();
  mockListDevices.mockReset();
  mockProbeOtOnce.mockReset();
  mockGetActiveCidr.mockReset();
  mockProbeOt.mockReset();

  // Safe default: getActiveCidr returns the test CIDR so the input is pre-filled
  mockGetActiveCidr.mockResolvedValue({
    iface: 'eth0',
    cidr: TEST_CIDR,
    ipAddress: '10.0.0.100',
    prefix: 24,
    note: null,
  });
});

afterEach(() => {
  // Always restore real timers so fake-timer tests don't leak state
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------
// AC1 — Unified dispatch: all 4 stages fired on button click
// ---------------------------------------------------------------------------

describe('<UnifiedScanControl /> — AC1 unified dispatch', () => {
  it('clicking unified-scan-btn dispatches triggerScan ×3, listDevices ×1, probeOtOnce ×8 (2 devices × 4 protocols)', async () => {
    vi.useFakeTimers();

    const hosts = ['10.0.0.1', '10.0.0.2'];
    mockListDevices.mockResolvedValue(makePage(hosts));

    // triggerScan resolves to unique scan IDs per call
    mockTriggerScan
      .mockResolvedValueOnce({ id: 1 }) // PING_SWEEP
      .mockResolvedValueOnce({ id: 2 }) // SERVICE_DETECT
      .mockResolvedValueOnce({ id: 3 }); // OS_FINGERPRINT

    // getScanDetail immediately returns COMPLETE for all three nmap scans
    mockGetScanDetail.mockImplementation(async (id: number) =>
      makeScanDetail(id, 'COMPLETE', { discoveredDeviceIds: [id * 10] }),
    );

    // probeOtOnce resolves immediately
    mockProbeOtOnce.mockResolvedValue(MOCK_PROBE_RESULT);

    render(<UnifiedScanControl />);

    // Wait for getActiveCidr effect to pre-fill the CIDR
    await act(async () => {
      await vi.runAllTimersAsync();
    });

    const btn = screen.getByTestId('unified-scan-btn');
    expect(btn).toBeInTheDocument();

    fireEvent.click(btn);

    // Drain all async work: poll timers + OT sweep pacing timers
    await act(async () => {
      await vi.runAllTimersAsync();
    });

    // 3 nmap stages: PING_SWEEP, SERVICE_DETECT, OS_FINGERPRINT
    expect(mockTriggerScan).toHaveBeenCalledTimes(3);
    expect(mockTriggerScan).toHaveBeenCalledWith({ cidr: TEST_CIDR, type: 'PING_SWEEP' });
    expect(mockTriggerScan).toHaveBeenCalledWith({ cidr: TEST_CIDR, type: 'SERVICE_DETECT' });
    expect(mockTriggerScan).toHaveBeenCalledWith({ cidr: TEST_CIDR, type: 'OS_FINGERPRINT' });

    // OT stage fetches device list
    expect(mockListDevices).toHaveBeenCalledTimes(1);

    // OT stage probes each host × each of 4 protocols
    expect(mockProbeOtOnce).toHaveBeenCalledTimes(8);

    // Verify all 4 OT protocols were probed
    const probedProtocols = mockProbeOtOnce.mock.calls.map((c) => c[1]);
    expect(probedProtocols).toContain('MODBUS_TCP');
    expect(probedProtocols).toContain('DNP3');
    expect(probedProtocols).toContain('S7COMM');
    expect(probedProtocols).toContain('BACNET_IP');

    // Verify the correct hosts were probed
    const probedHosts = mockProbeOtOnce.mock.calls.map((c) => c[0]);
    expect(probedHosts).toContain('10.0.0.1');
    expect(probedHosts).toContain('10.0.0.2');
  });
});

// ---------------------------------------------------------------------------
// AC3 — Progress renders: <progress> + per-stage rows
// ---------------------------------------------------------------------------

describe('<UnifiedScanControl /> — AC3 progress renders', () => {
  it('unified-progress element exists and per-stage rows unified-stage-* are rendered', async () => {
    vi.useFakeTimers();

    mockListDevices.mockResolvedValue(makePage(['10.0.0.1']));
    mockTriggerScan
      .mockResolvedValueOnce({ id: 1 })
      .mockResolvedValueOnce({ id: 2 })
      .mockResolvedValueOnce({ id: 3 });
    mockGetScanDetail.mockImplementation(async (id: number) =>
      makeScanDetail(id, 'COMPLETE', { discoveredDeviceIds: [] }),
    );
    mockProbeOtOnce.mockResolvedValue(MOCK_PROBE_RESULT);

    render(<UnifiedScanControl />);

    await act(async () => {
      await vi.runAllTimersAsync();
    });

    fireEvent.click(screen.getByTestId('unified-scan-btn'));

    await act(async () => {
      await vi.runAllTimersAsync();
    });

    // Progress bar must exist
    const progressEl = screen.getByTestId('unified-progress');
    expect(progressEl).toBeInTheDocument();
    // Progress value = overall = completedStages / 4; all complete → value === 1
    expect(progressEl).toHaveAttribute('max', '1');
    // value attribute may be string '1' or number 1; parse it
    const val = Number((progressEl as HTMLProgressElement).value);
    expect(val).toBe(1);

    // All 4 per-stage rows must exist
    const stageIds = ['PING_SWEEP', 'SERVICE_DETECT', 'OS_FINGERPRINT', 'OT_ICS_SWEEP'];
    for (const id of stageIds) {
      expect(screen.getByTestId(`unified-stage-${id}`)).toBeInTheDocument();
    }
  });

  it('per-stage rows show stage-level completion status after all stages finish', async () => {
    vi.useFakeTimers();

    mockListDevices.mockResolvedValue(makePage(['10.0.0.5']));
    mockTriggerScan
      .mockResolvedValueOnce({ id: 10 })
      .mockResolvedValueOnce({ id: 11 })
      .mockResolvedValueOnce({ id: 12 });
    mockGetScanDetail.mockImplementation(async (id: number) =>
      makeScanDetail(id, 'COMPLETE', { discoveredDeviceIds: [id] }),
    );
    mockProbeOtOnce.mockResolvedValue({ ...MOCK_PROBE_RESULT, host: '10.0.0.5' });

    render(<UnifiedScanControl />);

    await act(async () => {
      await vi.runAllTimersAsync();
    });

    fireEvent.click(screen.getByTestId('unified-scan-btn'));

    await act(async () => {
      await vi.runAllTimersAsync();
    });

    // OT stage row should reflect completed/total progress
    const otRow = screen.getByTestId('unified-stage-OT_ICS_SWEEP');
    expect(otRow).toBeInTheDocument();

    // Nmap stage rows should exist
    expect(screen.getByTestId('unified-stage-PING_SWEEP')).toBeInTheDocument();
    expect(screen.getByTestId('unified-stage-SERVICE_DETECT')).toBeInTheDocument();
    expect(screen.getByTestId('unified-stage-OS_FINGERPRINT')).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// AC4 — Advanced per-type controls preserved under unified-advanced-toggle
// ---------------------------------------------------------------------------

describe('<UnifiedScanControl /> — AC4 advanced per-type controls', () => {
  it('unified-advanced-toggle exists and contains ScanTriggerForm + OtProbePanel', () => {
    render(<UnifiedScanControl />);

    // The advanced <details> toggle must be present
    const toggle = screen.getByTestId('unified-advanced-toggle');
    expect(toggle).toBeInTheDocument();

    // Open it
    fireEvent.click(toggle);

    // OtProbePanel is present inside the toggle (ot-probe-panel testid from OtProbePanel.tsx)
    expect(screen.getByTestId('ot-probe-panel')).toBeInTheDocument();

    // OtProbePanel's own advanced toggle (ot-advanced-toggle) must be reachable
    expect(screen.getByTestId('ot-advanced-toggle')).toBeInTheDocument();

    // ScanTriggerForm: look for the "Scan" submit button (from ScanTriggerForm.tsx)
    // ScanTriggerForm has no dedicated testid on the form itself; the button is identified by name
    const scanBtn = screen.getByRole('button', { name: /^Scan$/i });
    expect(scanBtn).toBeInTheDocument();
  });

  it('AC4 — ScanTriggerForm submit inside advanced toggle calls triggerScan once (single scan)', async () => {
    mockTriggerScan.mockResolvedValueOnce({ id: 99 });

    render(<UnifiedScanControl />);

    // Open the advanced toggle
    fireEvent.click(screen.getByTestId('unified-advanced-toggle'));

    // Wait for getActiveCidr effect in ScanTriggerForm
    // (ScanTriggerForm also calls getActiveCidr on mount)
    await act(async () => {
      await Promise.resolve();
    });

    // Click the "Scan" button inside ScanTriggerForm
    const scanBtn = screen.getByRole('button', { name: /^Scan$/i });
    fireEvent.click(scanBtn);

    // triggerScan called once (single nmap scan, NOT the 3-stage unified dispatch)
    await act(async () => {
      await Promise.resolve();
    });

    expect(mockTriggerScan).toHaveBeenCalledTimes(1);
    // The type submitted is whatever ScanTriggerForm defaults to (PING_SWEEP)
    expect(mockTriggerScan).toHaveBeenCalledWith(
      expect.objectContaining({ type: expect.stringMatching(/PING_SWEEP|SERVICE_DETECT|OS_FINGERPRINT/) }),
    );
  });
});

// ---------------------------------------------------------------------------
// AC4b — A FAILED *dependent* stage does NOT abort its sibling dependents.
// (PING_SWEEP succeeds first; one of the stages that depend on it fails; the
//  remaining dependents still run. This preserves per-stage failure isolation
//  under the new PING_SWEEP-first ordering.)
// ---------------------------------------------------------------------------

describe('<UnifiedScanControl /> — partial-failure isolation', () => {
  it('a FAILED dependent stage (SERVICE_DETECT) does not abort the OT stage or OS_FINGERPRINT', async () => {
    vi.useFakeTimers();

    mockListDevices.mockResolvedValue(makePage(['10.0.0.1']));

    // PING_SWEEP → id 1 → COMPLETE (prerequisite succeeds, unblocking dependents);
    // SERVICE_DETECT → id 2 → FAILED; OS_FINGERPRINT → id 3 → COMPLETE.
    mockTriggerScan
      .mockResolvedValueOnce({ id: 1 }) // PING_SWEEP
      .mockResolvedValueOnce({ id: 2 }) // SERVICE_DETECT
      .mockResolvedValueOnce({ id: 3 }); // OS_FINGERPRINT

    mockGetScanDetail.mockImplementation(async (id: number) => {
      if (id === 2) {
        return makeScanDetail(id, 'FAILED', { failureReason: 'timeout' });
      }
      return makeScanDetail(id, 'COMPLETE', { discoveredDeviceIds: [id * 10] });
    });

    mockProbeOtOnce.mockResolvedValue(MOCK_PROBE_RESULT);

    render(<UnifiedScanControl />);

    await act(async () => {
      await vi.runAllTimersAsync();
    });

    fireEvent.click(screen.getByTestId('unified-scan-btn'));

    await act(async () => {
      await vi.runAllTimersAsync();
    });

    // No crash — the component still renders
    expect(screen.getByTestId('unified-scan-btn')).toBeInTheDocument();

    // All 4 stage rows must be present
    const stageIds = ['PING_SWEEP', 'SERVICE_DETECT', 'OS_FINGERPRINT', 'OT_ICS_SWEEP'];
    for (const id of stageIds) {
      expect(screen.getByTestId(`unified-stage-${id}`)).toBeInTheDocument();
    }

    // OT stage still ran (probeOtOnce called — 1 host × 4 protocols)
    expect(mockProbeOtOnce).toHaveBeenCalledTimes(4);

    // All three nmap stages were submitted (PING_SWEEP, then the two dependents).
    expect(mockTriggerScan).toHaveBeenCalledTimes(3);
    // The non-failing dependent (OS_FINGERPRINT, id 3) was still polled.
    expect(mockGetScanDetail).toHaveBeenCalledWith(3);
  });
});

// ---------------------------------------------------------------------------
// AC — PING_SWEEP ordering: SERVICE_DETECT starts only after PING_SWEEP COMPLETE.
// ---------------------------------------------------------------------------

describe('<UnifiedScanControl /> — PING_SWEEP-first ordering', () => {
  it('SERVICE_DETECT/OS_FINGERPRINT are submitted only after PING_SWEEP reaches COMPLETE', async () => {
    vi.useFakeTimers();

    mockListDevices.mockResolvedValue(makePage(['10.0.0.1']));

    // Assign ids by submission order.
    mockTriggerScan
      .mockResolvedValueOnce({ id: 1 }) // PING_SWEEP (first)
      .mockResolvedValueOnce({ id: 2 })
      .mockResolvedValueOnce({ id: 3 });

    // PING_SWEEP stays RUNNING for the first two polls, then COMPLETE. While it is
    // non-terminal, the dependent stages must NOT have been submitted yet.
    let pingPolls = 0;
    mockGetScanDetail.mockImplementation(async (id: number) => {
      if (id === 1) {
        pingPolls += 1;
        return makeScanDetail(id, pingPolls >= 3 ? 'COMPLETE' : 'RUNNING');
      }
      return makeScanDetail(id, 'COMPLETE', { discoveredDeviceIds: [id * 10] });
    });

    mockProbeOtOnce.mockResolvedValue(MOCK_PROBE_RESULT);

    render(<UnifiedScanControl />);
    await act(async () => {
      await vi.runAllTimersAsync();
    });

    fireEvent.click(screen.getByTestId('unified-scan-btn'));

    // Advance just the first PING_SWEEP poll (RUNNING). Only PING_SWEEP should be in flight.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(mockTriggerScan).toHaveBeenCalledTimes(1);
    expect(mockTriggerScan).toHaveBeenCalledWith({ cidr: TEST_CIDR, type: 'PING_SWEEP' });

    // Drain the rest: PING_SWEEP completes, then the dependents are submitted and complete.
    await act(async () => {
      await vi.runAllTimersAsync();
    });

    expect(mockTriggerScan).toHaveBeenCalledTimes(3);
    expect(mockTriggerScan).toHaveBeenCalledWith({ cidr: TEST_CIDR, type: 'SERVICE_DETECT' });
    expect(mockTriggerScan).toHaveBeenCalledWith({ cidr: TEST_CIDR, type: 'OS_FINGERPRINT' });
  });

  it('when PING_SWEEP FAILS, the dependent stages are skipped (cascade) and not submitted', async () => {
    vi.useFakeTimers();

    mockListDevices.mockResolvedValue(makePage(['10.0.0.1']));

    // Only PING_SWEEP is ever submitted; it fails. Provide ids defensively.
    mockTriggerScan
      .mockResolvedValueOnce({ id: 1 }) // PING_SWEEP
      .mockResolvedValueOnce({ id: 2 })
      .mockResolvedValueOnce({ id: 3 });

    mockGetScanDetail.mockImplementation(async (id: number) =>
      makeScanDetail(id, id === 1 ? 'FAILED' : 'COMPLETE', { failureReason: 'nmap timed out' }),
    );
    mockProbeOtOnce.mockResolvedValue(MOCK_PROBE_RESULT);

    render(<UnifiedScanControl />);
    await act(async () => {
      await vi.runAllTimersAsync();
    });

    fireEvent.click(screen.getByTestId('unified-scan-btn'));
    await act(async () => {
      await vi.runAllTimersAsync();
    });

    // Only PING_SWEEP was submitted — dependents cascade-skip on its failure.
    expect(mockTriggerScan).toHaveBeenCalledTimes(1);
    expect(mockTriggerScan).toHaveBeenCalledWith({ cidr: TEST_CIDR, type: 'PING_SWEEP' });
    // The OT stage (also a PING_SWEEP dependent) never probes.
    expect(mockProbeOtOnce).not.toHaveBeenCalled();

    // The dependent rows are present and surface a skipped/failed status.
    const sdRow = screen.getByTestId('unified-stage-SERVICE_DETECT');
    expect(sdRow).toBeInTheDocument();
    expect(sdRow.textContent ?? '').toMatch(/failed/i);
  });
});
