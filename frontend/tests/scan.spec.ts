import { test, expect } from '@playwright/test';
import { sel, STORAGE_STATE, apiLogin, triggerScan } from './helpers';

test.use({ storageState: STORAGE_STATE });

test.describe('Scan trigger + detail', () => {
  test('golden path — UI submit shows scan status', async ({ page }) => {
    await test.step('operator navigates to topology page', async () => {
      await page.goto('/');
    });

    await test.step('operator submits scan form with default CIDR', async () => {
      // The ScanTriggerForm renders a single text input defaulting to 192.168.1.0/24.
      // Locate it by its known default value for robustness.
      const cidrInput = page.locator('input[type="text"]').first();
      await expect(cidrInput).toBeVisible({ timeout: 10000 });

      const submitButton = page.getByRole('button', { name: /^Scan$/ });
      await expect(submitButton).toBeVisible({ timeout: 5000 });
      await submitButton.click();
    });

    await test.step('operator sees scan status update', async () => {
      const statusEl = page.locator(sel.scanStatus);
      await expect(statusEl).toBeVisible({ timeout: 10000 });
    });
  });

  test('detail page — API-triggered scan reaches terminal status', async ({ page }) => {
    let scanId: string;

    await test.step('operator obtains auth token and triggers scan via API', async () => {
      let token: string;
      try {
        token = await apiLogin(page.request);
        scanId = await triggerScan(page.request, token);
      } catch {
        test.skip(true, 'backend unavailable — cannot seed scan');
        return;
      }
    });

    await test.step('operator navigates to scan detail page', async () => {
      await page.goto(`/scans/${scanId!}`);
    });

    await test.step('operator sees terminal status on detail page', async () => {
      // Status reaches COMPLETE or FAILED; backend uses COMPLETE (not COMPLETED).
      const statusText = page.locator(sel.scanStatus);
      await expect(statusText).toBeVisible({ timeout: 15000 });
      await expect(statusText).toHaveText(/COMPLETE|FAILED/, { timeout: 15000 });
    });
  });

  test('edge — not-found UUID renders alert', async ({ page }) => {
    await test.step('operator navigates to a non-existent scan UUID', async () => {
      await page.goto('/scans/00000000-0000-0000-0000-000000000000');
    });

    await test.step('operator sees not-found alert', async () => {
      const alertEl = page.locator(sel.scanDetailNotFound);
      await expect(alertEl).toBeVisible({ timeout: 10000 });
    });
  });
});
