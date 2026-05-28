import { useCallback, useEffect, useState } from 'react';
import { api } from '../api/client';
import type { ScanPolicyDto, ScanType } from '../api/types';

interface Props {
  isAdmin: boolean;
}

const SCAN_TYPES: ScanType[] = ['PING_SWEEP', 'SERVICE_DETECT', 'OS_FINGERPRINT'];

/**
 * ADMIN-only management UI for cron-driven scan policies. VIEWER renders a
 * notice and never calls the backend (backend RBAC enforces regardless).
 */
export function ScanPolicyPanel({ isAdmin }: Props) {
  const [policies, setPolicies] = useState<ScanPolicyDto[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Form state
  const [name, setName] = useState('');
  const [cronExpression, setCronExpression] = useState('0 0 * * * *');
  const [cidr, setCidr] = useState('');
  const [scanType, setScanType] = useState<ScanType>('PING_SWEEP');
  const [enabled, setEnabled] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [formMsg, setFormMsg] = useState<string | null>(null);
  const [cidrEmpty, setCidrEmpty] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const page = await api.listScanPolicies();
      setPolicies(page.content);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to load policies');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!isAdmin) return;
    let cancelled = false;
    const run = async () => {
      setLoading(true);
      setError(null);
      try {
        const page = await api.listScanPolicies();
        if (cancelled) return;
        setPolicies(page.content);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'failed to load policies');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void run();
    return () => { cancelled = true; };
  }, [isAdmin]);

  // Prefill CIDR from the configured network interface on mount.
  // Functional guard prevents overwriting an operator-typed value if the
  // async response arrives late (mirrors ScanTriggerForm idiom).
  useEffect(() => {
    let cancelled = false;
    api.getActiveCidr().then(r => {
      if (cancelled) return;
      if (r?.cidr) {
        setCidr(prev => prev === '' ? (r.cidr ?? '') : prev);
        setCidrEmpty(false);
      } else {
        setCidrEmpty(true);
      }
    }).catch(() => {});
    return () => { cancelled = true; };
  }, []);

  if (!isAdmin) {
    return (
      <section
        aria-label="Scheduled scan policies"
        className="mt-6 border border-gray-200 rounded p-4 bg-gray-50"
      >
        <h2 className="text-base font-semibold text-gray-800 mb-2">
          Scheduled scan policies
        </h2>
        <p className="text-sm text-gray-600">ADMIN role required.</p>
      </section>
    );
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setFormMsg(null);
    try {
      await api.createScanPolicy({ name, cronExpression, cidr, scanType, enabled });
      setFormMsg('Policy created.');
      setName('');
      await refresh();
    } catch (err) {
      setFormMsg(err instanceof Error ? err.message : 'create failed');
    } finally {
      setSubmitting(false);
    }
  }

  async function handleToggle(p: ScanPolicyDto) {
    try {
      if (p.enabled) {
        await api.disableScanPolicy(p.id);
      } else {
        await api.enableScanPolicy(p.id);
      }
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'toggle failed');
    }
  }

  async function handleDelete(p: ScanPolicyDto) {
    if (!window.confirm(`Delete policy "${p.name}"?`)) return;
    try {
      await api.deleteScanPolicy(p.id);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'delete failed');
    }
  }

  return (
    <section
      aria-label="Scheduled scan policies"
      className="mt-6 border border-gray-200 rounded p-4 bg-white"
    >
      <h2 className="text-base font-semibold text-gray-800 mb-3">
        Scheduled scan policies
      </h2>

      <form onSubmit={handleCreate} className="grid grid-cols-2 gap-2 mb-4 text-sm">
        <label className="flex flex-col">
          Name
          <input
            data-testid="policy-name-input"
            value={name}
            onChange={e => setName(e.target.value)}
            required
            className="px-2 py-1 border border-gray-300 rounded"
          />
        </label>
        <label className="flex flex-col">
          Cron expression (6 fields, e.g. <code>0 0 * * * *</code>)
          <input
            data-testid="policy-cron-input"
            value={cronExpression}
            onChange={e => setCronExpression(e.target.value)}
            required
            className="px-2 py-1 border border-gray-300 rounded font-mono"
            title="Spring 6-field cron: second minute hour day-of-month month day-of-week"
          />
        </label>
        <label className="flex flex-col">
          CIDR
          <input
            data-testid="policy-cidr-input"
            value={cidr}
            onChange={e => setCidr(e.target.value)}
            required
            className="px-2 py-1 border border-gray-300 rounded font-mono"
          />
          {cidrEmpty && (
            <span
              data-testid="policy-cidr-hint"
              className="text-xs text-amber-700 mt-1"
            >
              No network CIDR configured — set one in Settings.
            </span>
          )}
        </label>
        <label className="flex flex-col">
          Scan type
          <select
            data-testid="policy-type-select"
            value={scanType}
            onChange={e => setScanType(e.target.value as ScanType)}
            className="px-2 py-1 border border-gray-300 rounded"
          >
            {SCAN_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-2 col-span-2">
          <input
            type="checkbox"
            data-testid="policy-enabled-checkbox"
            checked={enabled}
            onChange={e => setEnabled(e.target.checked)}
          />
          Enabled
        </label>
        <button
          type="submit"
          disabled={submitting}
          data-testid="policy-create-btn"
          className="col-span-2 px-3 py-1 bg-blue-600 text-white rounded text-sm hover:bg-blue-700 disabled:opacity-50"
        >
          {submitting ? 'Creating…' : 'Create policy'}
        </button>
        {formMsg && (
          <span className="col-span-2 text-sm" role="status">{formMsg}</span>
        )}
      </form>

      {loading && <p className="text-sm text-gray-500">Loading…</p>}
      {error && <p className="text-sm text-red-600" role="alert">{error}</p>}

      {policies.length === 0 && !loading ? (
        <p className="text-sm text-gray-500">No scheduled policies configured.</p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-600 border-b border-gray-200">
              <th className="py-1 pr-2">Name</th>
              <th className="py-1 pr-2">Cron</th>
              <th className="py-1 pr-2">CIDR</th>
              <th className="py-1 pr-2">Type</th>
              <th className="py-1 pr-2">Enabled</th>
              <th className="py-1 pr-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {policies.map(p => (
              <tr key={p.id} data-testid={`policy-row-${p.name}`} className="border-b border-gray-100">
                <td className="py-1 pr-2 font-medium">{p.name}</td>
                <td className="py-1 pr-2 font-mono text-xs">{p.cronExpression}</td>
                <td className="py-1 pr-2 font-mono text-xs">{p.cidr}</td>
                <td className="py-1 pr-2 text-xs">{p.scanType}</td>
                <td className="py-1 pr-2">{p.enabled ? 'yes' : 'no'}</td>
                <td className="py-1 pr-2 flex gap-2">
                  <button
                    type="button"
                    data-testid={`policy-toggle-${p.name}`}
                    onClick={() => handleToggle(p)}
                    className="px-2 py-0.5 text-xs border border-gray-300 rounded hover:bg-gray-100"
                  >
                    {p.enabled ? 'Disable' : 'Enable'}
                  </button>
                  <button
                    type="button"
                    data-testid={`policy-delete-${p.name}`}
                    onClick={() => handleDelete(p)}
                    className="px-2 py-0.5 text-xs border border-red-300 text-red-700 rounded hover:bg-red-50"
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
