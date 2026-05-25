import { useState, type KeyboardEvent } from 'react';

interface Props {
  value: string | null;
  isAdmin: boolean;
  onSave: (next: string) => Promise<void>;
  disabled?: boolean;
}

/**
 * Click-to-edit text input for the device hostname.
 *
 * - VIEWERs see plain text (or em-dash when null).
 * - ADMINs click to open an input. Enter or blur saves; Escape cancels without saving.
 *   Trims whitespace; rejects empty strings with an inline error.
 */
export function HostnameInlineEdit({ value, isAdmin, onSave, disabled }: Props) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value ?? '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isAdmin) {
    return <span data-testid="hostname-readonly">{value ?? '—'}</span>;
  }

  function startEdit() {
    setDraft(value ?? '');
    setError(null);
    setEditing(true);
  }

  async function commit() {
    const trimmed = draft.trim();
    if (trimmed.length === 0) {
      setError('Hostname cannot be empty');
      return;
    }
    if (trimmed === (value ?? '')) {
      setEditing(false);
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await onSave(trimmed);
      setEditing(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  }

  function handleKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') {
      e.preventDefault();
      void commit();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      setError(null);
      setEditing(false);
    }
  }

  if (!editing) {
    return (
      <button
        type="button"
        aria-label="Edit hostname"
        onClick={startEdit}
        disabled={disabled}
        className="px-1 py-0.5 hover:bg-gray-100 rounded text-left"
      >
        {value ?? '—'}
      </button>
    );
  }

  return (
    <span className="inline-flex items-center gap-1">
      <input
        type="text"
        aria-label="Hostname"
        value={draft}
        disabled={saving || disabled}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={() => { if (!saving) void commit(); }}
        onKeyDown={handleKeyDown}
        autoFocus
        className="border border-gray-300 rounded px-1 py-0.5 text-sm"
      />
      {saving && <span data-testid="hostname-saving" className="text-xs text-gray-500">…</span>}
      {error && <span role="alert" className="text-xs text-red-600">{error}</span>}
    </span>
  );
}
