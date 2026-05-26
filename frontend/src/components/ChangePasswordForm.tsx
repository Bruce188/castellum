import { useState, type FormEvent } from 'react';
import { api } from '../api/client';

interface Props {
  /**
   * Called on a successful 204. The caller decides whether to clear the
   * session (to force re-login) or just dismiss an overlay (first-login flow).
   */
  onSuccess?: () => void;
  /** Test hook — defaults to ChangePasswordForm. */
  variant?: 'inline' | 'modal';
}

const MIN_LEN = 8;

/**
 * Self-service password change form. Talks to {@code POST /api/auth/change-password}.
 * Renders a 204 success message + invokes {@code onSuccess}. Surfaces 429 / 401
 * with user-readable text. Performs client-side checks for minimum length and
 * confirm-match before hitting the wire — but the server is the authority.
 *
 * <p>Never logs or persists the new password anywhere. Form state lives in
 * component-local React state and is cleared as soon as the request resolves.
 */
export function ChangePasswordForm({ onSuccess, variant = 'inline' }: Props) {
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (submitting) return;
    setError(null);
    if (newPassword.length < MIN_LEN) {
      setError(`New password must be at least ${MIN_LEN} characters.`);
      return;
    }
    if (newPassword !== confirmNewPassword) {
      setError('New password and confirmation do not match.');
      return;
    }
    setSubmitting(true);
    try {
      await api.changePassword({ oldPassword, newPassword });
      // Clear local state immediately — do not leave the plaintext in memory
      // any longer than necessary.
      setOldPassword('');
      setNewPassword('');
      setConfirmNewPassword('');
      setDone(true);
      onSuccess?.();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'change failed';
      if (msg.startsWith('429')) {
        setError(msg.replace(/^429 /, ''));
      } else if (msg.startsWith('401')) {
        setError('Old password is incorrect.');
      } else {
        setError(msg);
      }
    } finally {
      setSubmitting(false);
    }
  }

  const wrapperClass =
    variant === 'modal'
      ? 'bg-white rounded-lg shadow-xl p-6 w-full max-w-md'
      : 'rounded border border-gray-200 bg-white p-4 mb-4';

  return (
    <section data-testid="change-password-form" className={wrapperClass}>
      <header className="mb-3">
        <h2 className="text-base font-semibold text-gray-800">Change my password</h2>
        <p className="text-xs text-gray-500 mt-0.5">
          You will need to sign in again with the new password after a successful change.
        </p>
      </header>
      {done ? (
        <div role="status" className="text-sm text-green-700 bg-green-50 border border-green-200 rounded p-2">
          Password changed. Please sign in again.
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-3" autoComplete="off">
          <label className="block text-sm">
            <span className="block text-gray-700 mb-1">Current password</span>
            <input
              type="password"
              data-testid="old-password-input"
              value={oldPassword}
              onChange={e => setOldPassword(e.target.value)}
              autoComplete="current-password"
              required
              className="w-full border border-gray-300 rounded px-2 py-1 text-sm"
            />
          </label>
          <label className="block text-sm">
            <span className="block text-gray-700 mb-1">New password (min {MIN_LEN})</span>
            <input
              type="password"
              data-testid="new-password-input"
              value={newPassword}
              onChange={e => setNewPassword(e.target.value)}
              autoComplete="new-password"
              minLength={MIN_LEN}
              required
              className="w-full border border-gray-300 rounded px-2 py-1 text-sm"
            />
          </label>
          <label className="block text-sm">
            <span className="block text-gray-700 mb-1">Confirm new password</span>
            <input
              type="password"
              data-testid="confirm-password-input"
              value={confirmNewPassword}
              onChange={e => setConfirmNewPassword(e.target.value)}
              autoComplete="new-password"
              minLength={MIN_LEN}
              required
              className="w-full border border-gray-300 rounded px-2 py-1 text-sm"
            />
          </label>
          {error && (
            <p role="alert" className="text-sm text-red-600">{error}</p>
          )}
          <button
            type="submit"
            disabled={submitting || oldPassword.length === 0 || newPassword.length < MIN_LEN}
            className="px-3 py-1 text-sm rounded bg-blue-600 text-white hover:bg-blue-700 disabled:bg-blue-300 disabled:cursor-not-allowed"
          >
            {submitting ? 'Changing…' : 'Change password'}
          </button>
        </form>
      )}
    </section>
  );
}
