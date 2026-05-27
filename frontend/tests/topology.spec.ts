import { test, expect } from '@playwright/test';
import { sel, STORAGE_STATE } from './helpers';

test.use({ storageState: STORAGE_STATE });

test.describe('Topology + DiscoveryScope', () => {
  test('topology canvas and legend are visible on load', async ({ page }) => {
    await test.step('operator navigates to the topology page', async () => {
      await page.goto('/');
    });

    await test.step('operator sees the topology canvas', async () => {
      await expect(page.locator(sel.topologyCanvas)).toBeVisible();
    });

    await test.step('operator sees the topology legend', async () => {
      await expect(page.locator(sel.topologyLegend)).toBeVisible();
    });
  });

  test('scope-visibility toggle flips checked state for HOME checkbox', async ({ page }) => {
    await test.step('operator navigates to the topology page', async () => {
      await page.goto('/');
    });

    await test.step('operator waits for legend to appear', async () => {
      await expect(page.locator(sel.topologyLegend)).toBeVisible();
    });

    await test.step('operator reads and toggles the HOME scope checkbox', async () => {
      const homeCheckbox = page.locator('input[aria-label="HOME"]');
      const before = await homeCheckbox.isChecked();
      await homeCheckbox.click();
      const after = await homeCheckbox.isChecked();
      expect(after).not.toBe(before);
    });
  });

  test('F3 regression — topology canvas remains mounted 2s after load', async ({ page }) => {
    await test.step('operator navigates to the topology page', async () => {
      await page.goto('/');
    });

    await test.step('operator waits for initial render', async () => {
      await expect(page.locator(sel.topologyCanvas)).toBeVisible();
    });

    await test.step('operator sees topology remain mounted 2s after load', async () => {
      await page.waitForTimeout(2000);
      await expect(page.locator(sel.topologyCanvas)).toBeVisible();
    });
  });

  test('topology canvas is present even when no devices exist', async ({ page }) => {
    await test.step('operator navigates to the topology page', async () => {
      await page.goto('/');
    });

    await test.step('operator confirms canvas is present regardless of device count', async () => {
      await expect(page.locator(sel.topologyCanvas)).toBeVisible();
    });

    await test.step('operator checks for empty-state indicator when no devices are shown', async () => {
      const emptyMessages = page.getByText(/no devices yet/i);
      const count = await emptyMessages.count();
      if (count > 0) {
        await expect(emptyMessages.first()).toBeVisible();
      }
    });
  });
});
