import type { ScanReport } from '../api/types';

/**
 * Serializes a {@link ScanReport} to a JSON string.
 * Implementer replaces this stub with the real serialization logic.
 */
export function scanReportToJsonString(_report: ScanReport): string {
  throw new Error('scanReportToJsonString not implemented');
}

/**
 * Builds a JSON {@link Blob} from {@link report} and triggers a browser download.
 * Mirrors the StixExportPanel Blob-download idiom.
 * Implementer replaces this stub with the real download logic.
 */
export function exportScanReportJson(_report: ScanReport): void {
  throw new Error('exportScanReportJson not implemented');
}
