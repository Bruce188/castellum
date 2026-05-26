import { useEffect, useState } from 'react';
import { api } from '../api/client';
import type { IntegrationConfigDto } from '../api/types';

interface Props {
  isAdmin: boolean;
}

interface MispFormState {
  url: string;
  apiKey: string;
}

const EMPTY: MispFormState = { url: '', apiKey: '' };

/**
 * ADMIN UI for the MISP integration. Same shape as {@code TaxiiConfigPanel}
 * but with a single API-key credential field. Push is disabled until both
 * URL and an API key (saved or newly entered) are present.
 */
export function MispConfigPanel({ isAdmin }: Props) {
  const [form, setForm] = useState<MispFormState>(EMPTY);
  const [credentialsSet, setCredentialsSet] = useState(false);
  const [lastPushAt, setLastPushAt] = useState<string | null>(null);
  const [lastPushStatus, setLastPushStatus] = useState<string | null>(null);
  const [savedConfig, setSavedConfig] = useState<IntegrationConfigDto | null>(null);
  const [saving, setSaving] = useState(false);
  const [pushing, setPushing] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isAdmin) return;
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  async function load() {
    setError(null);
    try {
      const cfg = await api.getIntegrationConfig('MISP');
      hydrate(cfg);
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('404')) {
        setSavedConfig(null);
        setCredentialsSet(false);
        return;
      }
      setError(err instanceof Error ? err.message : 'failed to load MISP config');
    }
  }

  function hydrate(cfg: IntegrationConfigDto) {
    setSavedConfig(cfg);
    setCredentialsSet(cfg.credentialsSet);
    setLastPushAt(cfg.lastPushAt);
    setLastPushStatus(cfg.lastPushStatus);
    const c = cfg.config ?? {};
    setForm({ url: (c.url as string) ?? '', apiKey: '' });
  }

  if (!isAdmin) {
    return (
      <section
        aria-label="MISP integration"
        className="mt-6 border border-gray-200 rounded p-4 bg-gray-50"
      >
        <h2 className="text-base font-semibold text-gray-800 mb-2">MISP integration</h2>
        <p className="text-sm text-gray-600">ADMIN role required.</p>
      </section>
    );
  }

  const configComplete = form.url.trim().length > 0
    && (credentialsSet || form.apiKey.length > 0);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setMsg(null);
    setError(null);
    try {
      const cfg = await api.saveIntegrationConfig('MISP', {
        config: { url: form.url.trim() },
        credentials: form.apiKey,
      });
      hydrate(cfg);
      setMsg('MISP configuration saved.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'save failed');
    } finally {
      setSaving(false);
    }
  }

  async function handlePush() {
    setPushing(true);
    setMsg(null);
    setError(null);
    try {
      const result = await api.pushIntegration('MISP');
      setLastPushAt(result.pushedAt);
      setLastPushStatus(result.lastPushStatus);
      setMsg(result.status === 'ok' ? 'Push complete.' : 'Push reported errors — see status below.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'push failed');
    } finally {
      setPushing(false);
    }
  }

  const pushDisabledReason = !configComplete
    ? 'Save a complete config (URL + API key) before pushing.'
    : '';

  return (
    <section
      aria-label="MISP integration"
      className="mt-6 border border-gray-200 rounded p-4 bg-white"
    >
      <h2 className="text-base font-semibold text-gray-800 mb-3">MISP integration</h2>
      <form onSubmit={handleSave} className="grid grid-cols-2 gap-2 mb-3 text-sm">
        <label className="flex flex-col col-span-2">
          MISP URL
          <input
            data-testid="misp-url-input"
            value={form.url}
            onChange={e => setForm({ ...form, url: e.target.value })}
            required
            className="px-2 py-1 border border-gray-300 rounded font-mono"
            placeholder="https://misp.example.com"
          />
        </label>
        <label className="flex flex-col col-span-2">
          API key
          <input
            data-testid="misp-api-key-input"
            type="password"
            value={form.apiKey}
            onChange={e => setForm({ ...form, apiKey: e.target.value })}
            className="px-2 py-1 border border-gray-300 rounded"
            placeholder={credentialsSet ? '••• (saved; leave blank to keep)' : ''}
          />
        </label>
        <div className="col-span-2 flex gap-2 items-center">
          <button
            type="submit"
            data-testid="misp-save-btn"
            disabled={saving}
            className="px-3 py-1 bg-blue-600 text-white rounded text-sm hover:bg-blue-700 disabled:opacity-50"
          >
            {saving ? 'Saving…' : 'Save'}
          </button>
          <button
            type="button"
            data-testid="misp-push-btn"
            onClick={handlePush}
            disabled={pushing || !configComplete}
            title={pushDisabledReason}
            className="px-3 py-1 border border-gray-400 rounded text-sm hover:bg-gray-100 disabled:opacity-50"
          >
            {pushing ? 'Pushing…' : 'Push now'}
          </button>
          {savedConfig === null && (
            <span className="text-xs text-gray-500">No MISP config saved yet.</span>
          )}
        </div>
      </form>

      {msg && (
        <p className="text-sm text-green-700" role="status" data-testid="misp-msg">{msg}</p>
      )}
      {error && (
        <p className="text-sm text-red-600" role="alert" data-testid="misp-error">{error}</p>
      )}

      <dl className="mt-2 text-sm text-gray-700">
        <div className="flex gap-2">
          <dt className="font-semibold">Last push:</dt>
          <dd data-testid="misp-last-push-at">{lastPushAt ?? '(never)'}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="font-semibold">Status:</dt>
          <dd data-testid="misp-last-push-status">{lastPushStatus ?? '(no pushes yet)'}</dd>
        </div>
      </dl>
    </section>
  );
}
