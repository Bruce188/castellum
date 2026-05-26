import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook } from '@testing-library/react';
import { useScanStatus } from '../hooks/useScanStatus';
import { api } from '../api/client';
import type { ScanDetail } from '../api/types';

const STORAGE_KEY = 'castellum.lastScanId';

function flushMicrotasks(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

describe('useScanStatus', () => {
  beforeEach(() => {
    window.localStorage.clear();
    const mockScan: ScanDetail = {
      id: 0,
      cidr: '10.0.0.0/24',
      scanType: 'SERVICE_DETECT',
      status: 'RUNNING',
      requestedAt: '2026-01-01T00:00:00Z',
      completedAt: null,
      discoveredDeviceIds: [],
    };
    vi.spyOn(api, 'getScanDetail').mockResolvedValue(mockScan);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    window.localStorage.clear();
  });

  it('useScanStatus_withNullArgAndStoredId_issuesExactlyOneGetScanOnMount', async () => {
    window.localStorage.setItem(STORAGE_KEY, '42');
    renderHook(() => useScanStatus(null));
    await flushMicrotasks();
    const calls = (api.getScanDetail as unknown as { mock: { calls: unknown[][] } }).mock.calls;
    expect(calls.length).toBe(1);
    expect(calls[0][0]).toBe(42);
  });

  it('useScanStatus_withExplicitScanId_issuesExactlyOneGetScanOnMount', async () => {
    renderHook(() => useScanStatus(99));
    await flushMicrotasks();
    const calls = (api.getScanDetail as unknown as { mock: { calls: unknown[][] } }).mock.calls;
    expect(calls.length).toBe(1);
    expect(calls[0][0]).toBe(99);
  });

  it('useScanStatus_unmount_stopsPolling', async () => {
    vi.useFakeTimers();
    try {
      const { unmount } = renderHook(() => useScanStatus(7));
      // First synchronous tick from mount — count it.
      await Promise.resolve();
      const callsBefore = (api.getScanDetail as unknown as { mock: { calls: unknown[][] } }).mock.calls.length;
      unmount();
      vi.advanceTimersByTime(15_000);
      await Promise.resolve();
      const callsAfter = (api.getScanDetail as unknown as { mock: { calls: unknown[][] } }).mock.calls.length;
      // After unmount, no new calls (interval was cleared).
      expect(callsAfter).toBe(callsBefore);
    } finally {
      vi.useRealTimers();
    }
  });
});
