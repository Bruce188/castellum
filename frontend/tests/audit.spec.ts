import { test, expect } from '@playwright/test';
import { STORAGE_STATE } from './helpers';
import fs from 'node:fs';

test.use({ storageState: STORAGE_STATE });

test.describe('Audit log + CSV export', () => {
  test('audit page renders heading and CSV download produces a non-empty file', async ({ page }) => {
    await test.step('operator navigates to the audit page', async () => {
      await page.goto('/audit');
    });

    await test.step('operator sees the Audit Log heading', async () => {
      await expect(page.getByRole('heading', { name: /Audit Log/i })).toBeVisible();
    });

    await test.step('operator clicks Download CSV and receives a non-empty file', async () => {
      const downloadPromise = page.waitForEvent('download');
      await page.getByRole('button', { name: /Download CSV/i }).click();
      const download = await downloadPromise;

      const filePath = await download.path();
      expect(filePath).not.toBeNull();
      expect(filePath).toBeTruthy();
      const size = fs.statSync(filePath as string).size;
      expect(size).toBeGreaterThan(0);

      expect(download.suggestedFilename()).toMatch(/\.csv$/i);
    });
  });
});
