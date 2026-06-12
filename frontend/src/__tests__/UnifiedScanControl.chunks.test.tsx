/**
 * RED-phase tests for the chunked-scan frontend — UnifiedScanControl chunk
 * fraction display on the running nmap stage row.
 *
 * Locked design pinned here:
 *   - While an nmap stage is running AND chunksTotal != null && chunksTotal > 1,
 *     its row renders the fraction text `${chunksDone ?? 0}/${chunksTotal} chunks`
 *     (OT fraction precedent). Indirectly this also pins StageProgress/StageState
 *     gaining optional chunksTotal/chunksDone and the existing spread-fold in
 *     unifiedScan.ts propagating them.
 *   - When chunksTotal is absent OR === 1, NO chunk fraction is rendered —
 *     legacy display (scanStatus text) unchanged. (GUARD — passes today; keeps
 *     GREEN from rendering the fraction unconditionally.)
 *   - SUBMIT payloads are UNCHANGED — deliberately NOT asserted here (the
 *     exact pins live in UnifiedScanControl.test.tsx).
 *
 * Harness mirrors UnifiedScanControl.test.tsx: mocked api client, REAL
 * runUnifiedScan + makeNmapStage, fake timers driven explicitly (no waitFor).
 */

import { render, screen, fireEvent, act, within } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

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
    probeOt: vi.fn(),
    discoverDocker: vi.fn(),
  },
}));

const mockTriggerScan = vi.mocked(api.triggerScan);
const mockGetScanDetail = vi.mocked(api.getScanDetail);
const mockListDevices = vi.mocked(api.listDevices);
const mockProbeOtOnce = vi.mocked(api.probeOtOnce);
const mockGetActiveCidr = vi.mocked(api.getActiveCidr);
const mockProbeOt = vi.mocked(api.probeOt);
const mockDiscoverDocker = vi.mocked(api.discoverDocker);

// ---------------------------------------------------------------------------
// Helpers (mirroring UnifiedScanControl.test.tsx)
// ---------------------------------------------------------------------------

const TEST_CIDR = '10.20.0.0/16';

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
      publishesHostPort: false,
      deviceRole: 'UNKNOWN' as const,
      originHostIp: 'local',
      originHostName: null,
      networkName: null,
    })),
    totalElements: ips.length,
    totalPages: 1,
    number: 0,
    size: 200,
  };
}

const MOCK_PROBE_RESULT = {
  host: '10.20.0.1',
  port: 502,
  protocol: 'MODBUS_TCP' as const,
  vendor: 'ACME',
  product: 'PLC-1',
  version: '1.0',
  rawFields: {},
  deviceId: 1,
  serviceId: 1,
  observedAt: '2026-06-12T00:00:00Z',
};

function makeScanDetail(
  id: number,
  status: 'PENDING' | 'RUNNING' | 'COMPLETE' | 'FAILED',
  extra: Partial<{
    discoveredDeviceIds: number[];
    failureReason: string;
    chunksTotal: number | null;
    chunksDone: number | null;
  }> = {},
) {
  return {
    id,
    cidr: TEST_CIDR,
    scanType: 'PING_SWEEP' as const,
    status,
    requestedAt: '2026-06-12T00:00:00Z',
    completedAt: status === 'COMPLETE' || status === 'FAILED' ? '2026-06-12T00:01:00Z' : null,
    failureReason: extra.failureReason ?? null,
    retryCount: 0,
    discoveredDeviceIds: extra.discoveredDeviceIds ?? [],
    chunksTotal: extra.chunksTotal,
    chunksDone: extra.chunksDone,
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
  mockDiscoverDocker.mockReset();

  mockDiscoverDocker.mockResolvedValue({ containers: 0, gateways: 0, updated: 0, deviceIds: [] });
  mockGetActiveCidr.mockResolvedValue({
    iface: 'eth0',
    cidr: TEST_CIDR,
    ipAddress: '10.20.0.100',
    prefix: 16,
    note: null,
  });
  mockListDevices.mockResolvedValue(makePage(['10.20.0.1']));
  mockProbeOtOnce.mockResolvedValue(MOCK_PROBE_RESULT);
});

afterEach(() => {
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------
// Multi-chunk: fraction rendered while the nmap stage is running
// ---------------------------------------------------------------------------

describe('<UnifiedScanControl /> — chunk fraction on running nmap row', () => {
  it('renders "2/4 chunks" then "3/4 chunks" on the PING_SWEEP row while a multi-chunk scan runs', async () => {
    vi.useFakeTimers();

    mockTriggerScan
      .mockResolvedValueOnce({ id: 1 }) // PING_SWEEP
      .mockResolvedValueOnce({ id: 2 }) // SERVICE_DETECT
      .mockResolvedValueOnce({ id: 3 }); // OS_FINGERPRINT

    // PING_SWEEP (id 1): poll 1 → RUNNING 2/4, poll 2 → RUNNING 3/4, poll ≥3 → COMPLETE 4/4.
    let pingPolls = 0;
    mockGetScanDetail.mockImplementation(async (id: number) => {
      if (id === 1) {
        pingPolls += 1;
        if (pingPolls === 1) {
          return makeScanDetail(id, 'RUNNING', { chunksTotal: 4, chunksDone: 2 });
        }
        if (pingPolls === 2) {
          return makeScanDetail(id, 'RUNNING', { chunksTotal: 4, chunksDone: 3 });
        }
        return makeScanDetail(id, 'COMPLETE', { chunksTotal: 4, chunksDone: 4 });
      }
      return makeScanDetail(id, 'COMPLETE', { discoveredDeviceIds: [id * 10] });
    });

    render(<UnifiedScanControl />);
    await act(async () => {
      await vi.runAllTimersAsync();
    });

    fireEvent.click(screen.getByTestId('unified-scan-btn'));

    // First poll (delay 0): RUNNING with chunksDone 2 of 4.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    const row = screen.getByTestId('unified-stage-PING_SWEEP');
    expect(row.textContent).toContain('2/4 chunks');

    // Second poll (one poll interval later): chunksDone advanced to 3.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(screen.getByTestId('unified-stage-PING_SWEEP').textContent).toContain('3/4 chunks');

    // Drain everything: PING_SWEEP completes, dependents run to completion.
    await act(async () => {
      await vi.runAllTimersAsync();
    });
    expect(screen.getByTestId('unified-stage-PING_SWEEP').textContent).toContain('complete');
  });

  it('renders "0/4 chunks" (the ?? 0 fallback) when chunksDone is null while running', async () => {
    vi.useFakeTimers();

    mockTriggerScan
      .mockResolvedValueOnce({ id: 1 })
      .mockResolvedValueOnce({ id: 2 })
      .mockResolvedValueOnce({ id: 3 });

    let pingPolls = 0;
    mockGetScanDetail.mockImplementation(async (id: number) => {
      if (id === 1) {
        pingPolls += 1;
        if (pingPolls === 1) {
          return makeScanDetail(id, 'RUNNING', { chunksTotal: 4, chunksDone: null });
        }
        return makeScanDetail(id, 'COMPLETE', { chunksTotal: 4, chunksDone: 4 });
      }
      return makeScanDetail(id, 'COMPLETE');
    });

    render(<UnifiedScanControl />);
    await act(async () => {
      await vi.runAllTimersAsync();
    });

    fireEvent.click(screen.getByTestId('unified-scan-btn'));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(screen.getByTestId('unified-stage-PING_SWEEP').textContent).toContain('0/4 chunks');

    await act(async () => {
      await vi.runAllTimersAsync();
    });
  });
});

// ---------------------------------------------------------------------------
// GUARD — single-chunk / absent chunk fields: NO fraction, legacy display
// (passes today; pins that GREEN must not render the fraction unconditionally)
// ---------------------------------------------------------------------------

describe('<UnifiedScanControl /> — no chunk fraction for single-chunk or legacy scans (guard)', () => {
  it('renders NO "chunks" text when chunksTotal === 1 (single-chunk) or absent (legacy)', async () => {
    vi.useFakeTimers();

    mockTriggerScan
      .mockResolvedValueOnce({ id: 1 }) // PING_SWEEP
      .mockResolvedValueOnce({ id: 2 }) // SERVICE_DETECT
      .mockResolvedValueOnce({ id: 3 }); // OS_FINGERPRINT

    // PING_SWEEP (id 1): single-chunk scan — RUNNING with chunksTotal 1, then COMPLETE.
    // SERVICE_DETECT (id 2): legacy shape — RUNNING with NO chunk fields for the first
    // three polls (tolerates poll-scheduling jitter around stage dispatch), then COMPLETE.
    let pingPolls = 0;
    let sdPolls = 0;
    mockGetScanDetail.mockImplementation(async (id: number) => {
      if (id === 1) {
        pingPolls += 1;
        if (pingPolls === 1) {
          return makeScanDetail(id, 'RUNNING', { chunksTotal: 1, chunksDone: 0 });
        }
        return makeScanDetail(id, 'COMPLETE', { chunksTotal: 1, chunksDone: 1 });
      }
      if (id === 2) {
        sdPolls += 1;
        if (sdPolls <= 3) {
          return makeScanDetail(id, 'RUNNING');
        }
        return makeScanDetail(id, 'COMPLETE');
      }
      return makeScanDetail(id, 'COMPLETE');
    });

    render(<UnifiedScanControl />);
    await act(async () => {
      await vi.runAllTimersAsync();
    });

    fireEvent.click(screen.getByTestId('unified-scan-btn'));

    // First PING_SWEEP poll: RUNNING with chunksTotal === 1 → legacy display only.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    const pingRow = screen.getByTestId('unified-stage-PING_SWEEP');
    expect(pingRow.textContent).toContain('RUNNING');
    expect(within(pingRow).queryByText(/chunks/)).toBeNull();
    expect(screen.queryByText(/chunks/)).toBeNull();

    // Let PING_SWEEP complete; SERVICE_DETECT dispatches and polls while
    // RUNNING with no chunk fields → legacy display only. Advance two full
    // poll intervals so at least one SERVICE_DETECT poll has reported.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    const sdRow = screen.getByTestId('unified-stage-SERVICE_DETECT');
    expect(sdRow.textContent).toContain('RUNNING');
    expect(within(sdRow).queryByText(/chunks/)).toBeNull();

    // Drain to completion so no timers leak.
    await act(async () => {
      await vi.runAllTimersAsync();
    });
    expect(screen.queryByText(/chunks/)).toBeNull();
  });
});
