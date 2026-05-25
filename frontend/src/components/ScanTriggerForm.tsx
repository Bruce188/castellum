import { useState } from 'react';
import { api } from '../api/client';
import type { ScanType } from '../api/types';
import { useScanStatus } from '../hooks/useScanStatus';

const SCAN_TYPES: ScanType[] = ['PING_SWEEP', 'SERVICE_DETECT', 'OS_FINGERPRINT'];

interface Props {
  onScanSubmitted?: (id: number) => void;
}

export function ScanTriggerForm({ onScanSubmitted }: Props) {
  const [cidr, setCidr] = useState('192.168.1.0/24');
  const [type, setType] = useState<ScanType>('PING_SWEEP');
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const scan = useScanStatus(activeScanId);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const result = await api.triggerScan({ cidr, type });
      setActiveScanId(result.id);
      onScanSubmitted?.(result.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'submit failed');
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex items-center gap-2 px-4 py-2 border-b border-gray-200 bg-gray-50">
      <label className="text-sm font-medium">CIDR
        <input
          type="text"
          value={cidr}
          onChange={e => setCidr(e.target.value)}
          className="ml-2 px-2 py-1 border border-gray-300 rounded text-sm w-44"
          required
          title="CIDR notation, e.g. 192.168.1.0/24 — the subnet the scanner will sweep."
        />
      </label>
      <label className="text-sm font-medium">Type
        <select
          value={type}
          onChange={e => setType(e.target.value as ScanType)}
          className="ml-2 px-2 py-1 border border-gray-300 rounded text-sm"
          title="Scan type: PING_SWEEP (host discovery) | SERVICE_DETECT (port + banner) | OS_FINGERPRINT (OS guess)."
        >
          {SCAN_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
      </label>
      <button type="submit" className="px-3 py-1 bg-blue-600 text-white rounded text-sm hover:bg-blue-700">
        Scan
      </button>
      {scan && (
        <span className="ml-4 text-sm text-gray-700" data-testid="scan-status">
          scan #{scan.id}: <strong>{scan.status}</strong>
        </span>
      )}
      {error && (
        <span className="ml-4 text-sm text-red-600" role="alert">{error}</span>
      )}
    </form>
  );
}
