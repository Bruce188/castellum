import type { ScanReport } from '../api/types';

/**
 * Serializes a {@link ScanReport} to a pretty-printed JSON string that
 * round-trips cleanly (no lossy transforms).
 */
export function scanReportToJsonString(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}

/**
 * Builds a JSON {@link Blob} from {@link report} and triggers a browser
 * download. Mirrors the StixExportPanel Blob-download idiom.
 */
export function exportScanReportJson(report: ScanReport): void {
  const json = scanReportToJsonString(report);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `castellum-scan-report-${report.summary.scanId}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
