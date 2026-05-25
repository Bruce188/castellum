import { test, expect, type Page } from '@playwright/test';

const APP = 'http://127.0.0.1:5173';
const ADMIN = { username: 'admin', password: 'admin' };

async function signIn(page: Page, who: { username: string; password: string }) {
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

    // Verify the AuditLogPanel is rendered (ADMIN-only)
    await expect(page.getByRole('heading', { name: /Audit Log/i })).toBeVisible({ timeout: 5000 });

    // Trigger a scan via the form
    const cidrInput = page.locator('input[placeholder*="CIDR"], input[name*="cidr"], input[type="text"]').first();
    await cidrInput.fill('10.0.0.0/30');

    // Select scan type if present
    const scanTypeSelect = page.locator('select[name*="type"], select[name*="scan"]').first();
    const scanTypeCount = await scanTypeSelect.count();
    if (scanTypeCount > 0) {
      await scanTypeSelect.selectOption('PING_SWEEP');
    }

    await page.click('button:has-text("Submit Scan")');

    // Wait for the scan to be acknowledged (scan submitted feedback)
    await expect(
      page.locator('text=/Scan submitted|Scan #|submitt/i').first()
    ).toBeVisible({ timeout: 8000 });

    // Click Refresh on AuditLogPanel to trigger a fresh fetch
    const refreshBtn = page.locator('button:has-text("Refresh")').first();
    await refreshBtn.scrollIntoViewIfNeeded();
    await refreshBtn.click();

    // AC#4: SCAN_SUBMIT row appears in table within 5s
    await expect(
      page.locator('table').locator('td', { hasText: 'SCAN_SUBMIT' }).first()
    ).toBeVisible({ timeout: 5000 });

    // Click the row to expand and verify CIDR in JSON payload
    await page.locator('table').locator('td', { hasText: 'SCAN_SUBMIT' }).first().click();
    await expect(page.locator('pre').filter({ hasText: '10.0.0.0/30' }).first()).toBeVisible({ timeout: 2000 });
  });
});
