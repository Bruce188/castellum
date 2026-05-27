import { test as setup, expect } from '@playwright/test';
import { CREDS, STORAGE_STATE, sel } from './helpers';

/**
 * Authenticates as the bootstrap admin and persists storage state for reuse by
 * the feature-group specs (each opts in via `test.use({ storageState })`).
 *
 * C3 (see docs/analysis-v41.md): if the bootstrap admin still requires a
 * password rotation, App.tsx renders <ForcePasswordRotation /> instead of the
 * routed shell, so the captured state would not be "logged into the app
 * proper". We fail fast with an actionable message rather than capture a broken
 * state — CI must provision an admin whose rotation is already satisfied.
 */
setup('authenticate as admin', async ({ page }) => {
  await page.goto('/');
  await page.fill(sel.loginUser, CREDS.username);
  await page.fill(sel.loginPass, CREDS.password);
  await page.click(sel.loginSubmit);

  // Wait for a post-login DOM signal — the topology canvas (success) OR the
  // rotation gate (failure) — to render BEFORE reading rotation state. The app
  // writes the JWT to localStorage before React re-renders to the rotation
  // screen, so reading rotation visibility off the bare JWT wait can read false
  // falsely and defeat the C3 fail-fast guard.
  const canvas = page.locator(sel.topologyCanvas);
  const rotation = page.getByTestId('force-password-rotation');
  await expect(canvas.or(rotation)).toBeVisible({ timeout: 10_000 });

  const onRotation = await rotation.isVisible().catch(() => false);
  expect(
    onRotation,
    'Bootstrap admin requires a password rotation — provision an admin with rotation satisfied (E2E_ADMIN_PASSWORD must match the bootstrap hash and not be flagged mustChangePassword).',
  ).toBe(false);

  // Confirm the JWT landed before persisting storage state for reuse.
  await page.waitForFunction(
    key => localStorage.getItem(key) !== null,
    sel.jwtKey,
    { timeout: 5_000 },
  );

  await page.context().storageState({ path: STORAGE_STATE });
});
