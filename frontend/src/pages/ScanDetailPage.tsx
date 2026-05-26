import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api } from '../api/client';
import type { Device, ScanDetail } from '../api/types';

type ErrorKind = 'not-found' | 'other';

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const parsedId = id !== undefined ? Number(id) : NaN;
  const scanId = Number.isFinite(parsedId) ? parsedId : null;

  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState<boolean>(scanId !== null);
  const [error, setError] = useState<{ kind: ErrorKind } | null>(
    scanId === null ? { kind: 'not-found' } : null,
  );

  // Fetch the scan detail
  useEffect(() => {
    if (scanId === null) return;
    let cancelled = false;
    (async () => {
      if (cancelled) return;
      setLoading(true);
      setError(null);
      try {
        const data = await api.getScanDetail(scanId);
        if (cancelled) return;
        setScan(data);
      } catch (err) {
        if (cancelled) return;
        const msg = err instanceof Error ? err.message : '';
        setError({ kind: msg.startsWith('404') ? 'not-found' : 'other' });
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [scanId]);

  // Resolve discovered devices to (hostname, IP) rows.
  useEffect(() => {
    if (scan === null || scan.discoveredDeviceIds.length === 0) return;
    let cancelled = false;
    (async () => {
      const results = await Promise.allSettled(
        scan.discoveredDeviceIds.map(did => api.getDevice(did))
      );
      if (cancelled) return;
      const ok = results
        .filter((r): r is PromiseFulfilledResult<Device> => r.status === 'fulfilled')
        .map(r => r.value);
      setDevices(ok);
    })();
    return () => {
      cancelled = true;
      // Reset rows on cleanup so a subsequent scan-id change starts empty
      // until the fresh device lookups resolve.
      setDevices([]);
    };
  }, [scan]);

  if (loading) {
    return (
      <div role="status" data-testid="scan-detail-loading" className="p-4">
        Loading scan…
      </div>
    );
  }

  if (error?.kind === 'not-found') {
    return (
      <div className="p-4">
        <div role="alert" data-testid="scan-detail-not-found" className="mb-3">
          Scan not found.
        </div>
        <Link to="/scans" className="text-blue-700 hover:underline">
          ← Back to scans
        </Link>
      </div>
    );
  }

  if (error?.kind === 'other' || scan === null) {
    return (
      <div className="p-4">
        <div role="alert" className="mb-3">Failed to load scan.</div>
        <Link to="/scans" className="text-blue-700 hover:underline">
          ← Back to scans
        </Link>
      </div>
    );
  }

  return (
    <div className="p-4">
      <div className="mb-4 flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">Scan #{scan.id}</h1>
        <Link to="/scans" className="text-blue-700 hover:underline text-sm">
          ← Back to scans
        </Link>
      </div>

      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm mb-6">
        <dt className="text-gray-500">Status</dt><dd>{scan.status}</dd>
        <dt className="text-gray-500">CIDR</dt><dd className="font-mono">{scan.cidr}</dd>
        <dt className="text-gray-500">Type</dt><dd>{scan.scanType}</dd>
        <dt className="text-gray-500">Requested at</dt><dd>{scan.requestedAt}</dd>
        <dt className="text-gray-500">Completed at</dt><dd>{scan.completedAt ?? '—'}</dd>
        <dt className="text-gray-500">Retry count</dt><dd>{scan.retryCount ?? 0}</dd>
        {scan.failureReason && (
          <>
            <dt className="text-gray-500">Failure reason</dt>
            <dd className="text-red-600">{scan.failureReason}</dd>
          </>
        )}
      </dl>

      <section>
        <h2 className="text-lg font-semibold mb-1">
          Devices discovered ({devices.length})
        </h2>
        <p className="text-xs text-gray-500 mb-2">
          Devices first seen during the scan window. Re-discovered devices
          are not listed.
        </p>
        {devices.length === 0 ? (
          <p className="text-sm text-gray-500">No devices discovered.</p>
        ) : (
          <table className="w-full text-sm" data-testid="discovered-devices-table">
            <thead>
              <tr className="text-left text-gray-500 border-b">
                <th className="py-1 pr-4">IP</th>
                <th className="py-1">Hostname</th>
              </tr>
            </thead>
            <tbody>
              {devices.map(d => (
                <tr key={d.id} className="border-b last:border-b-0">
                  <td className="py-1 pr-4 font-mono">{d.ipAddress}</td>
                  <td className="py-1">{d.hostname ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
