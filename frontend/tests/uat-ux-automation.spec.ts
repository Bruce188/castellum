import { test, expect, type Page } from '@playwright/test';
import { CREDS, VIEWER_CREDS, STORAGE_STATE, apiLogin } from './helpers';

/**
 * UAT — UX-automation features F5–F9 (the role/button flows the autonomous
 * pipeline run could not exercise: ADMIN-gated panels needing an authed
 * browser). Each test renders a panel and drives its primary affordance.
 *
 * Assertions are deliberately TOLERANT of backend reachability: this local
 * stack has no reachable scan targets / PLCs / TAXII server, so a primary
 * action may surface an error or complete instantly over an empty fleet. UAT
 * here verifies the affordance RENDERS, is wired, and TRANSITIONS without
 * crashing the panel — it does not assert successful backend completion.
 */

// ---------------------------------------------------------------------------
// ADMIN flows — storage state from auth.setup (bootstrap admin).
// ---------------------------------------------------------------------------
test.describe('UAT F5–F9 (admin)', () => {
  test.use({ storageState: STORAGE_STATE });

  test('F5 — TAXII integration: preset select + reachability probe', async ({ page }) => {
    await page.goto('/settings');
    const select = page.getByTestId('taxii-preset-select');
    await expect(select).toBeVisible({ timeout: 10_000 });

    // Pick the first real preset (index 0 is the "Choose a preset…" placeholder).
    const optionValues = await select.locator('option').evaluateAll(
      els => els.map(e => (e as HTMLOptionElement).value).filter(Boolean),
    );
    expect(optionValues.length, 'TAXII presets should be offered').toBeGreaterThan(0);
    await select.selectOption(optionValues[0]);

    // A reachability indicator must appear (any state — reachable/unreachable is
    // fine; the point is the probe wiring fires and renders a verdict).
    await expect(page.getByTestId('taxii-reachability')).toBeVisible({ timeout: 15_000 });
  });

  test('F6 — one-button passive scanning activate/deactivate', async ({ page }) => {
    await page.goto('/settings');
    const panel = page.getByTestId('discovery-control-panel');
    await expect(panel).toBeVisible({ timeout: 10_000 });

    const activate = page.getByTestId('passive-activate-btn').first();
    await expect(activate).toBeVisible();

    if (await activate.isEnabled()) {
      await activate.click();
      // Activation may flip into the in-flight state (Scanning… + Deactivate)
      // or complete quickly when the backend discovery call resolves fast — in
      // this env there are no real passive sources, so timing varies. Either way
      // the UAT signal is: the button is wired, and clicking it leaves the panel
      // mounted with the activate affordance still present (no crash). The
      // deterministic in-flight/abort path is covered by component tests.
      const deactivate = page.getByTestId('passive-deactivate-btn');
      if (await deactivate.isVisible({ timeout: 3_000 }).catch(() => false)) {
        await deactivate.click();
      }
      await expect(panel).toBeVisible();
      // Tolerate slow re-render of the idle Activate affordance after the toggle dance.
      await expect(page.getByTestId('passive-activate-btn').first()).toBeVisible({ timeout: 15_000 });
    } else {
      // No discoverable passive sources in this env → button correctly disabled.
      // Rendering + correct disabled state is the UAT signal here.
      await expect(activate).toBeDisabled();
    }
  });

  test('F7 — one-action OT/ICS sweep starts + stops', async ({ page }) => {
    await page.goto('/settings');
    const panel = page.getByTestId('ot-probe-panel');
    await expect(panel).toBeVisible({ timeout: 10_000 });

    const sweep = page.getByTestId('ot-sweep-all-btn');
    await expect(sweep).toBeVisible();
    await expect(sweep).toBeEnabled();
    await sweep.click();

    // Over an empty fleet the sweep can complete instantly; over a populated one
    // it shows the live grid/progress. Any of grid/progress/error proves wiring.
    const outcome = page
      .getByTestId('ot-sweep-grid')
      .or(page.getByTestId('ot-sweep-progress'))
      .or(page.getByTestId('ot-sweep-error'))
      .first();
    await expect(outcome).toBeVisible({ timeout: 15_000 });

    // If still sweeping, the operator stop control must work.
    const stop = page.getByTestId('ot-sweep-stop-btn');
    if (await stop.isVisible().catch(() => false)) {
      await stop.click();
      await expect(sweep).toBeVisible({ timeout: 10_000 });
    }
  });

  test('F8 — unified "Scan this network" starts + stops', async ({ page }) => {
    await page.goto('/scans');
    const btn = page.getByTestId('unified-scan-btn');
    await expect(btn).toBeVisible({ timeout: 10_000 });
    await expect(btn).toBeEnabled();
    await btn.click();

    // "Starts": clicking dispatches the scan (the button disables). Over an empty CI fleet the
    // stages can finish near-instantly, so the Stop control may not still be visible by the time
    // we look — tolerate both (cf. F7's instant-completion handling). "Stops": if Stop is shown,
    // clicking it aborts. Either way the panel must settle back to an idle, clickable Scan button
    // without crashing.
    const stop = page.getByTestId('unified-scan-stop-btn');
    if (await stop.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await stop.click().catch(() => {});
    }
    await expect(btn).toBeVisible({ timeout: 15_000 });
    await expect(btn).toBeEnabled({ timeout: 15_000 });
  });

  test('F9 — feed-sync schedule panel renders + enable/disable toggles', async ({ page }) => {
    await page.goto('/settings');
    const panel = page.getByTestId('feed-sync-panel');
    await expect(panel).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId('schedule-cron')).toBeVisible();
    await expect(page.getByTestId('schedule-next-run')).toBeVisible();

    const toggle = page.getByTestId('schedule-toggle');
    await expect(toggle).toBeVisible();
    const before = (await toggle.textContent())?.trim();
    await toggle.click();
    // The toggle hits the backend enable/disable endpoint and re-renders. The
    // panel must remain mounted and the label must settle (may flip or, on a
    // transient backend error, revert) — the UAT signal is "no crash".
    await expect(panel).toBeVisible();
    await expect(toggle).toBeVisible({ timeout: 10_000 });
    // Restore prior state if it flipped, to leave the schedule as found.
    const after = (await toggle.textContent())?.trim();
    if (after && before && after !== before) {
      await toggle.click().catch(() => {});
      await expect(panel).toBeVisible();
    }
  });
});

// ---------------------------------------------------------------------------
// VIEWER RBAC — admin-gated affordances must render read-only / be absent.
// ---------------------------------------------------------------------------
test.describe('UAT F5–F9 (viewer RBAC)', () => {
  async function signInViewer(page: Page) {
    await apiLogin(page.request, VIEWER_CREDS).catch(() => {});
    await page.goto('/');
    await page.fill('input[autocomplete="username"]', VIEWER_CREDS.username);
    await page.fill('input[autocomplete="current-password"]', VIEWER_CREDS.password);
    await page.click('button[type="submit"]');
    await page.waitForFunction(() => localStorage.getItem('castellum.jwt') !== null, { timeout: 10_000 });
  }

  test('viewer sees Settings panels read-only (no admin actions)', async ({ page }) => {
    await signInViewer(page);
    await page.goto('/settings');

    // Feed-sync: read-only notice present, ADMIN-only schedule toggle absent.
    await expect(page.getByTestId('feed-sync-panel')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(/Read-only — ADMIN required to trigger sync/i)).toBeVisible();
    await expect(page.getByTestId('schedule-toggle')).toHaveCount(0);

    // OT probe + passive discovery: read-only notices present.
    await expect(page.getByText(/Read-only — ADMIN required to run probes/i)).toBeVisible();
    await expect(page.getByText(/Read-only — ADMIN required to run sweeps/i)).toBeVisible();
  });

  test('viewer cannot start a unified scan', async ({ page }) => {
    await signInViewer(page);
    await page.goto('/scans');
    const btn = page.getByTestId('unified-scan-btn');
    // Either the control is absent for viewers, or rendered disabled — both are
    // valid RBAC outcomes. A visible+enabled scan button would be a finding.
    if (await btn.isVisible().catch(() => false)) {
      await expect(btn).toBeDisabled();
    } else {
      await expect(btn).toHaveCount(0);
    }
  });
});
