import { useEffect, useState } from 'react';
import { api } from '../api/client';
import type { IntegrationConfigDto } from '../api/types';

interface Props {
  isAdmin: boolean;
}

interface TaxiiFormState {
  url: string;
  apiRoot: string;
  collectionId: string;
  username: string;
  password: string;
}

const EMPTY: TaxiiFormState = {
  url: '', apiRoot: '', collectionId: '', username: '', password: '',
};

/**
 * ADMIN UI for the TAXII integration. GETs the current config on mount,
 * lets the operator edit it, and exposes a "Push now" button that hits
 * POST /api/integrations/TAXII/push and surfaces the result inline.
 *
 * <p>Push is disabled when the config is incomplete (no URL yet) — the
 * tooltip explains why so the operator does not need to guess.
 */
export function TaxiiConfigPanel({ isAdmin }: Props) {
  const [form, setForm] = useState<TaxiiFormState>(EMPTY);
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
      const cfg = await api.getIntegrationConfig('TAXII');
      hydrate(cfg);
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('404')) {
        // No config saved yet — leave the form blank.
        setSavedConfig(null);
        setCredentialsSet(false);
        return;
      }
      setError(err instanceof Error ? err.message : 'failed to load TAXII config');
    }
  }

  function hydrate(cfg: IntegrationConfigDto) {
    setSavedConfig(cfg);
    setCredentialsSet(cfg.credentialsSet);
    setLastPushAt(cfg.lastPushAt);
    setLastPushStatus(cfg.lastPushStatus);
    const c = cfg.config ?? {};
    setForm({
      url: (c.url as string) ?? '',
      apiRoot: (c.apiRoot as string) ?? '',
      collectionId: (c.collectionId as string) ?? '',
      username: (c.username as string) ?? '',
      password: '',
    });
  }

  if (!isAdmin) {
    return (
      <section
        aria-label="TAXII integration"
        className="mt-6 border border-gray-200 rounded p-4 bg-gray-50"
      >
        <h2 className="text-base font-semibold text-gray-800 mb-2">TAXII integration</h2>
        <p className="text-sm text-gray-600">ADMIN role required.</p>
      </section>
    );
  }

  const configComplete = form.url.trim().length > 0
    && form.collectionId.trim().length > 0
    && (credentialsSet || form.password.length > 0);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setMsg(null);
    setError(null);
    try {
      const cfg = await api.saveIntegrationConfig('TAXII', {
        config: {
          url: form.url.trim(),
          apiRoot: form.apiRoot.trim(),
          collectionId: form.collectionId.trim(),
          username: form.username.trim(),
        },
        credentials: form.password,
      });
      hydrate(cfg);
      setMsg('TAXII configuration saved.');
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
      const result = await api.pushIntegration('TAXII');
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
    ? 'Save a complete config (URL + collection ID + credentials) before pushing.'
    : '';

  return (
    <section
      aria-label="TAXII integration"
      className="mt-6 border border-gray-200 rounded p-4 bg-white"
    >
      <h2 className="text-base font-semibold text-gray-800 mb-3">TAXII integration</h2>
      <form onSubmit={handleSave} className="grid grid-cols-2 gap-2 mb-3 text-sm">
        <label className="flex flex-col">
          Server URL
          <input
            data-testid="taxii-url-input"
            value={form.url}
            onChange={e => setForm({ ...form, url: e.target.value })}
            required
            className="px-2 py-1 border border-gray-300 rounded font-mono"
            placeholder="https://taxii.example.com"
          />
        </label>
        <label className="flex flex-col">
          API root
          <input
            data-testid="taxii-api-root-input"
            value={form.apiRoot}
            onChange={e => setForm({ ...form, apiRoot: e.target.value })}
            className="px-2 py-1 border border-gray-300 rounded font-mono"
            placeholder="/api/v21"
          />
        </label>
        <label className="flex flex-col">
          Collection ID
          <input
            data-testid="taxii-collection-input"
            value={form.collectionId}
            onChange={e => setForm({ ...form, collectionId: e.target.value })}
            required
            className="px-2 py-1 border border-gray-300 rounded font-mono"
          />
        </label>
        <label className="flex flex-col">
          Username
          <input
            data-testid="taxii-username-input"
            value={form.username}
            onChange={e => setForm({ ...form, username: e.target.value })}
            className="px-2 py-1 border border-gray-300 rounded"
          />
        </label>
        <label className="flex flex-col col-span-2">
          Password
          <input
            data-testid="taxii-password-input"
            type="password"
            value={form.password}
            onChange={e => setForm({ ...form, password: e.target.value })}
            className="px-2 py-1 border border-gray-300 rounded"
            placeholder={credentialsSet ? '••• (saved; leave blank to keep)' : ''}
          />
        </label>
        <div className="col-span-2 flex gap-2 items-center">
          <button
            type="submit"
            data-testid="taxii-save-btn"
            disabled={saving}
            className="px-3 py-1 bg-blue-600 text-white rounded text-sm hover:bg-blue-700 disabled:opacity-50"
          >
            {saving ? 'Saving…' : 'Save'}
          </button>
          <button
            type="button"
            data-testid="taxii-push-btn"
            onClick={handlePush}
            disabled={pushing || !configComplete}
            title={pushDisabledReason}
            className="px-3 py-1 border border-gray-400 rounded text-sm hover:bg-gray-100 disabled:opacity-50"
          >
            {pushing ? 'Pushing…' : 'Push now'}
          </button>
          {savedConfig === null && (
            <span className="text-xs text-gray-500">No TAXII config saved yet.</span>
          )}
        </div>
      </form>

      {msg && (
        <p className="text-sm text-green-700" role="status" data-testid="taxii-msg">{msg}</p>
      )}
      {error && (
        <p className="text-sm text-red-600" role="alert" data-testid="taxii-error">{error}</p>
      )}

      <dl className="mt-2 text-sm text-gray-700">
        <div className="flex gap-2">
          <dt className="font-semibold">Last push:</dt>
          <dd data-testid="taxii-last-push-at">{lastPushAt ?? '(never)'}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="font-semibold">Status:</dt>
          <dd data-testid="taxii-last-push-status">{lastPushStatus ?? '(no pushes yet)'}</dd>
        </div>
      </dl>
    </section>
  );
}
