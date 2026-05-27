import { test, expect, type Page } from '@playwright/test';
import { CREDS, BASE_URL, apiLogin, triggerScan } from './helpers';

const APP = BASE_URL;
const ADMIN = CREDS;

async function signIn(page: Page, who: { username: string; password: string }) {
  // Warm-up login flips lastLoginAt server-side so the UI login below lands in
  // the app shell rather than the first-login password-rotation gate.
  await apiLogin(page.request, who).catch(() => {});
  await page.goto(APP);
  await page.fill('input[autocomplete="username"]', who.username);
  await page.fill('input[autocomplete="current-password"]', who.password);
  await page.click('button[type="submit"]');
  await page.waitForFunction(
    () => localStorage.getItem('castellum.jwt') !== null,
    { timeout: 10000 }
  );
}

test.describe('audit log viewer', () => {
  test('admin sees new audit row within 5s of triggering a scan', async ({ page }) => {
    await signIn(page, ADMIN);

    // /audit hosts only the audit log panel (no scan form), so trigger the scan
    // through the API. SCAN_SUBMIT is audited at submit time with the scan id as
    // resourceId and the full scan (including cidr) as the JSON payload.
    const token = await apiLogin(page.request, ADMIN);
    const cidr = '10.0.0.0/30';
    const scanId = await triggerScan(page.request, token, cidr);

    await page.goto(`${APP}/audit`);

    // Verify the AuditLogPanel is rendered (ADMIN-only)
    await expect(page.getByRole('heading', { name: /Audit Log/i })).toBeVisible({ timeout: 5000 });

    // Narrow to SCAN_SUBMIT and apply so the newest events sit on page 0.
    await page.locator('select').first().selectOption('SCAN_SUBMIT');
    await page.getByRole('button', { name: /^Apply$/ }).click();

    // AC#4: the SCAN_SUBMIT row for our scan id appears within 5s. Match the
    // Resource ID cell exactly so a different scan's row can't be picked.
    const row = page.locator('tbody tr', {
      has: page.locator('td', { hasText: new RegExp(`^${scanId}$`) }),
    }).first();
    await expect(row).toBeVisible({ timeout: 5000 });

    // Expand the row and verify the CIDR is in the JSON payload.
    await row.click();
    await expect(page.locator('pre').filter({ hasText: cidr }).first()).toBeVisible({ timeout: 2000 });
  });
});
