import { useState } from 'react';
import type { Device } from '../api/types';

interface Props {
  device: Device;
  isAdmin: boolean;
  onConfirmed: () => Promise<void>;
}

/**
 * Two-step "decommission" (DELETE) for a device.
 *
 * - VIEWERs see nothing (component returns null).
 * - ADMINs see a red button. Click opens a confirm modal that requires typing the device's
 *   hostname (or IP, when hostname is null) verbatim to enable the final {@code Confirm}
 *   button. Cancel is always enabled. While the DELETE is in flight the dialog shows a
 *   spinner and disables both buttons.
 */
export function DecommissionButton({ device, isAdmin, onConfirmed }: Props) {
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isAdmin) return null;

  const requiredText = device.hostname ?? device.ipAddress;
  const canConfirm = typed === requiredText && !busy;

  function openDialog() {
    setTyped('');
    setError(null);
    setOpen(true);
  }

  function close() {
    if (busy) return;
    setOpen(false);
    setTyped('');
    setError(null);
  }

  async function confirm() {
    if (!canConfirm) return;
    setBusy(true);
    setError(null);
    try {
      await onConfirmed();
      setOpen(false);
      setTyped('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delete failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={openDialog}
        className="text-sm bg-red-600 hover:bg-red-700 text-white rounded px-3 py-1"
      >
        Decommission
      </button>
      {open && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Confirm decommission"
          data-testid="decommission-dialog"
          className="fixed inset-0 bg-black/40 flex items-center justify-center z-50"
        >
          <div className="bg-white rounded shadow-xl p-4 w-96 max-w-full">
            <h3 className="font-semibold text-base mb-2">Decommission device</h3>
            <p className="text-sm text-gray-700 mb-2">
              This permanently removes the device and its scan history. Type{' '}
              <code className="bg-gray-100 px-1 rounded">{requiredText}</code> to confirm.
            </p>
            <input
              type="text"
              aria-label="Type hostname to confirm"
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              disabled={busy}
              autoFocus
              className="w-full border border-gray-300 rounded px-2 py-1 text-sm mb-2"
            />
            {error && <p role="alert" className="text-xs text-red-600 mb-2">{error}</p>}
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={close}
                disabled={busy}
                className="px-3 py-1 text-sm border border-gray-300 rounded hover:bg-gray-100"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirm}
                disabled={!canConfirm}
                className="px-3 py-1 text-sm rounded text-white bg-red-600 hover:bg-red-700 disabled:bg-red-300 disabled:cursor-not-allowed"
              >
                {busy ? 'Removing…' : 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
