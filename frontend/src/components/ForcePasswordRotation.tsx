import { ChangePasswordForm } from './ChangePasswordForm';
import { clearMustChangePassword } from '../hooks/useAuth';

/**
 * Full-screen overlay rendered when {@code auth.mustChangePassword} is set.
 * Blocks all other navigation — it is mounted in place of the routed app
 * rather than as a sibling, so no Routes can match.
 *
 * <p>On success: clears the {@code mustChangePassword} flag and reloads the
 * page so the user lands on the fresh login screen (the prior JWT is now
 * invalidated by the server-side {@code tokenVersion} bump, so the next API
 * call would 401 anyway — this just gives the user a clean restart).
 */
export function ForcePasswordRotation() {
  function handleSuccess() {
    clearMustChangePassword();
    // Give the success banner a beat to render before forcing reload.
    setTimeout(() => {
      window.location.reload();
    }, 1200);
  }

  return (
    <div
      data-testid="force-password-rotation"
      role="dialog"
      aria-modal="true"
      aria-label="Password rotation required"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
    >
      <div className="max-w-md w-full">
        <div className="mb-3 text-white text-sm bg-amber-600 rounded px-3 py-2">
          You are signed in with a bootstrap account. Please choose a new password
          before continuing — this is a one-time, required step.
        </div>
        <ChangePasswordForm variant="modal" onSuccess={handleSuccess} />
      </div>
    </div>
  );
}
