import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ScanReport } from '../api/types';

// Import the helper — does not exist yet; tests will fail red until implemented.
import { exportScanReportJson, scanReportToJsonString } from '../lib/scanReportExport';

const mockReport: ScanReport = {
  summary: {
    scanId: 7,
    cidr: '10.0.0.0/24',
    scanType: 'SERVICE_DETECT',
    status: 'COMPLETE',
    requestedAt: '2024-01-01T10:00:00Z',
    completedAt: '2024-01-01T10:05:00Z',
    durationMillis: 300000,
    failureReason: null,
    retryCount: 0,
    deviceCount: 1,
    serviceCount: 2,
    cveCount: 1,
  },
  devices: [
    {
      id: 10,
      ipAddress: '10.0.0.10',
      hostname: 'router',
      delta: 'new',
      services: [
        { id: 101, port: 80, protocol: 'tcp', name: 'http', version: 'nginx/1.24' },
        { id: 102, port: 443, protocol: 'tcp', name: 'https', version: null },
      ],
      cveIds: ['CVE-2024-9999'],
    },
  ],
};

describe('scanReportToJsonString()', () => {
  it('returns a valid JSON string that round-trips to the original report', () => {
    const json = scanReportToJsonString(mockReport);
    expect(typeof json).toBe('string');
    const parsed = JSON.parse(json) as ScanReport;
    expect(parsed.summary.scanId).toBe(7);
    expect(parsed.summary.deviceCount).toBe(1);
    expect(parsed.devices).toHaveLength(1);
  });

  it('preserves summary fields in the JSON output', () => {
    const json = scanReportToJsonString(mockReport);
    const parsed = JSON.parse(json) as ScanReport;
    expect(parsed.summary.cidr).toBe('10.0.0.0/24');
    expect(parsed.summary.scanType).toBe('SERVICE_DETECT');
    expect(parsed.summary.status).toBe('COMPLETE');
    expect(parsed.summary.durationMillis).toBe(300000);
    expect(parsed.summary.serviceCount).toBe(2);
    expect(parsed.summary.cveCount).toBe(1);
  });

  it('preserves device delta values in the JSON output', () => {
    const json = scanReportToJsonString(mockReport);
    const parsed = JSON.parse(json) as ScanReport;
    expect(parsed.devices[0].delta).toBe('new');
  });

  it('preserves nested services in the JSON output', () => {
    const json = scanReportToJsonString(mockReport);
    const parsed = JSON.parse(json) as ScanReport;
    expect(parsed.devices[0].services).toHaveLength(2);
    expect(parsed.devices[0].services[0].port).toBe(80);
    expect(parsed.devices[0].services[1].version).toBeNull();
  });

  it('preserves cveIds array in the JSON output', () => {
    const json = scanReportToJsonString(mockReport);
    const parsed = JSON.parse(json) as ScanReport;
    expect(parsed.devices[0].cveIds).toEqual(['CVE-2024-9999']);
  });

  it('handles a report with no devices (empty snapshot)', () => {
    const emptyReport: ScanReport = { ...mockReport, devices: [] };
    const json = scanReportToJsonString(emptyReport);
    const parsed = JSON.parse(json) as ScanReport;
    expect(parsed.devices).toHaveLength(0);
  });
});

describe('exportScanReportJson()', () => {
  beforeEach(() => {
    // jsdom does not implement URL.createObjectURL — stub it (same as StixExportPanel tests).
    if (typeof URL.createObjectURL !== 'function') {
      Object.defineProperty(URL, 'createObjectURL', {
        value: vi.fn(() => 'blob:mock-scan-report'),
        writable: true,
      });
      Object.defineProperty(URL, 'revokeObjectURL', {
        value: vi.fn(),
        writable: true,
      });
    } else {
      vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock-scan-report');
      vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    }
  });

  it('triggers a download by appending an anchor element to document.body', () => {
    const appendSpy = vi.spyOn(document.body, 'appendChild');

    exportScanReportJson(mockReport);

    const downloadAnchor = appendSpy.mock.calls.find(
      ([el]) => el instanceof HTMLAnchorElement && el.download.endsWith('.json')
    );
    expect(downloadAnchor).toBeTruthy();
  });

  it('produces a Blob with type application/json', () => {
    const createObjectURL = vi.spyOn(URL, 'createObjectURL');

    exportScanReportJson(mockReport);

    // createObjectURL must have been called with a Blob of type application/json
    expect(createObjectURL).toHaveBeenCalled();
    const blobArg = createObjectURL.mock.calls[0][0] as Blob;
    expect(blobArg.type).toBe('application/json');
  });

  it('uses a filename that includes the scan id', () => {
    const appendSpy = vi.spyOn(document.body, 'appendChild');

    exportScanReportJson(mockReport);

    const downloadAnchor = appendSpy.mock.calls.find(
      ([el]) => el instanceof HTMLAnchorElement && el.download.endsWith('.json')
    );
    expect(downloadAnchor).toBeTruthy();
    const anchor = downloadAnchor![0] as HTMLAnchorElement;
    // Filename should contain the scan id (7) so files are distinguishable
    expect(anchor.download).toContain('7');
  });

  it('the Blob content round-trips to a valid ScanReport', async () => {
    let capturedBlob: Blob | undefined;
    vi.spyOn(URL, 'createObjectURL').mockImplementation((blob) => {
      capturedBlob = blob as Blob;
      return 'blob:mock';
    });

    exportScanReportJson(mockReport);

    expect(capturedBlob).toBeDefined();
    const text = await capturedBlob!.text();
    const parsed = JSON.parse(text) as ScanReport;
    expect(parsed.summary.scanId).toBe(7);
    expect(parsed.devices[0].delta).toBe('new');
  });
});
