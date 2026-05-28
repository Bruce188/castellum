import { useEffect, useRef, useState } from 'react';
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

const DOCKER_TAXII_URL = 'http://localhost:9000/taxii2/';

const TAXII_PRESETS: { label: string; url: string; collectionId?: string }[] = [
  {
    label: 'MITRE ATT&CK (TAXII 2.1)',
    url: 'https://cti-taxii.mitre.org/taxii/',
    collectionId: '95ecc380-afe9-11e4-9b6c-751b66dd541e',
  },
  {
    label: 'OpenTAXII demo',
    url: 'http://taxii.demo.example.com/taxii2/',
  },
];

type ProbeStatus = 'idle' | 'checking' | 'reachable' | 'unreachable';

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
  const [detected, setDetected] = useState(false);
  const [probeStatus, setProbeStatus] = useState<ProbeStatus>('idle');

  // Holds a ref to the last loaded savedConfig so detect() can read it
  // without a stale closure over state.
  const savedConfigRef = useRef<IntegrationConfigDto | null>(null);
  const formRef = useRef<TaxiiFormState>(EMPTY);

  useEffect(() => {
    formRef.current = form;
  }, [form]);

  useEffect(() => {
    if (!isAdmin) return;
    let cancelled = false;

    async function run() {
      await load();
      if (cancelled) return;
      void detect(cancelled);
    }

    function detect(isCancelled: boolean) {
      return (async () => {
        try {
          const result = await api.probeIntegration('TAXII', DOCKER_TAXII_URL);
          if (isCancelled) return;
          if (result.reachable) {
            prefillIfBlank({ url: DOCKER_TAXII_URL }, savedConfigRef.current);
            setDetected(true);
          }
        } catch {
          // Detection failure is silent
        }
      })();
    }

    void run();

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  async function load() {
    setError(null);
    try {
      const cfg = await api.getIntegrationConfig('TAXII');
      savedConfigRef.current = cfg;
      hydrate(cfg);
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('404')) {
        // No config saved yet — leave the form blank.
        savedConfigRef.current = null;
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
    const next: TaxiiFormState = {
      url: (c.url as string) ?? '',
      apiRoot: (c.apiRoot as string) ?? '',
      collectionId: (c.collectionId as string) ?? '',
      username: (c.username as string) ?? '',
      password: '',
    };
    formRef.current = next;
    setForm(next);
  }

  /**
   * Prefill fields only when the saved config has a blank/absent value for that
   * field AND the current form field is also blank. The saved DB config is the
   * "manually saved" authority — never clobber it.
   */
  function prefillIfBlank(
    next: Partial<TaxiiFormState>,
    currentSavedConfig: IntegrationConfigDto | null,
  ) {
    const savedCfg = currentSavedConfig?.config ?? {};
    setForm(prev => {
      const updated = { ...prev };
      let changed = false;
      for (const key of Object.keys(next) as (keyof TaxiiFormState)[]) {
        const savedVal = (savedCfg[key] as string | undefined) ?? '';
        const formVal = prev[key].trim();
        if (savedVal === '' && formVal === '') {
          updated[key] = next[key] as string;
          changed = true;
        }
      }
      return changed ? updated : prev;
    });
  }

  async function handlePresetChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const url = e.target.value;
    if (!url) return;
    const preset = TAXII_PRESETS.find(p => p.url === url);
    if (!preset) return;

    // Operator-initiated: fill URL and optionally collectionId directly
    setForm(prev => ({
      ...prev,
      url: preset.url,
      ...(preset.collectionId ? { collectionId: preset.collectionId } : {}),
    }));

    // Probe reachability
    setProbeStatus('checking');
    try {
      const result = await api.probeIntegration('TAXII', preset.url, preset.collectionId);
      setProbeStatus(result.reachable ? 'reachable' : 'unreachable');
    } catch {
      setProbeStatus('unreachable');
    }
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

      <div className="mb-3">
        <label className="text-sm flex flex-col">
          Preset server
          <select
            data-testid="taxii-preset-select"
            defaultValue=""
            onChange={handlePresetChange}
            className="px-2 py-1 border border-gray-300 rounded text-sm"
          >
            <option value="">Choose a preset…</option>
            {TAXII_PRESETS.map(p => (
              <option key={p.url} value={p.url}>{p.label}</option>
            ))}
          </select>
        </label>
        {probeStatus !== 'idle' && (
          <span
            data-testid="taxii-reachability"
            data-status={probeStatus}
            className={
              probeStatus === 'checking'
                ? 'text-xs text-gray-500 ml-1'
                : probeStatus === 'reachable'
                  ? 'text-xs text-green-700 ml-1'
                  : 'text-xs text-red-600 ml-1'
            }
          >
            {probeStatus === 'checking' && 'Checking reachability…'}
            {probeStatus === 'reachable' && 'reachable'}
            {probeStatus === 'unreachable' && 'unreachable'}
          </span>
        )}
      </div>

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
          {detected && (
            <span data-testid="taxii-detected-note" className="text-xs text-blue-600 mt-0.5">
              auto-detected (editable)
            </span>
          )}
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
