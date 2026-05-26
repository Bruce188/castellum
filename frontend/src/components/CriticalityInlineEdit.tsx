import { useState } from 'react';
import type { Criticality } from '../api/types';

const OPTIONS: Criticality[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

interface Props {
  value: Criticality;
  isAdmin: boolean;
  onSave: (next: Criticality) => Promise<void>;
  disabled?: boolean;
}

/**
 * Click-to-edit dropdown for {@link Criticality}.
 *
 * - VIEWERs (or callers passing {@code isAdmin=false}) see the current value as plain text.
 * - ADMINs see the value; click swaps it for a {@code <select>}. Selecting a new option calls
 *   {@code onSave} and collapses back to text on success. A failing save keeps the dropdown
 *   open and surfaces the error inline.
 */
export function CriticalityInlineEdit({ value, isAdmin, onSave, disabled }: Props) {
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isAdmin) {
    return <span data-testid="criticality-readonly">{value}</span>;
  }

  async function handleChange(next: Criticality) {
    if (next === value) {
      setEditing(false);
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await onSave(next);
      setEditing(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  }

  if (!editing) {
    return (
      <button
        type="button"
        aria-label="Edit criticality"
        onClick={() => setEditing(true)}
        disabled={disabled}
        className="px-1 py-0.5 hover:bg-gray-100 rounded text-left"
      >
        {value}
        <svg
          data-testid="edit-affordance"
          aria-hidden="true"
          width="12"
          height="12"
          viewBox="0 0 16 16"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          className="inline-block ml-1 text-gray-400"
        >
          <path d="M11.5 1.5l3 3-9 9H2.5v-3l9-9z" />
        </svg>
      </button>
    );
  }

  return (
    <span className="inline-flex items-center gap-1">
      <select
        aria-label="Criticality"
        value={value}
        disabled={saving || disabled}
        onChange={(e) => handleChange(e.target.value as Criticality)}
        onBlur={() => { if (!saving) setEditing(false); }}
        autoFocus
        className="border border-gray-300 rounded px-1 py-0.5 text-sm"
        title="Criticality: LOW / MEDIUM / HIGH / CRITICAL — drives the composite risk score (CRITICAL weights 1.00, LOW weights 0.00)."
      >
        {OPTIONS.map(o => <option key={o} value={o}>{o}</option>)}
      </select>
      {saving && <span data-testid="criticality-saving" className="text-xs text-gray-500">…</span>}
      {error && <span role="alert" className="text-xs text-red-600">{error}</span>}
    </span>
  );
}
