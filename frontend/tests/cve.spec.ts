import { test, expect } from '@playwright/test';
import { sel, STORAGE_STATE } from './helpers';

test.use({ storageState: STORAGE_STATE });

test.describe('CVE + KEV + EPSS + Composite', () => {
  test('column headers are visible on the CVE list page', async ({ page }) => {
    await test.step('operator navigates to /cves', async () => {
      await page.goto('/cves');
    });

    await test.step('operator sees key column headers', async () => {
      await expect(page.getByText('CVE ID')).toBeVisible();
      await expect(page.getByText('CVSS v3.1')).toBeVisible();
      await expect(page.getByText('KEV')).toBeVisible();
      await expect(page.getByText('EPSS')).toBeVisible();
      await expect(page.getByText('Composite')).toBeVisible();
    });
  });

  test('clicking the Composite header sorts by composite', async ({ page }) => {
    await test.step('operator navigates to /cves', async () => {
      await page.goto('/cves');
    });

    await test.step('operator clicks the Composite column header', async () => {
      const compositeHeader = page
        .getByRole('columnheader', { name: /Composite/i })
        .first();
      const fallback = page.getByText('Composite', { exact: false }).first();

      const headerCount = await compositeHeader.count();
      if (headerCount > 0) {
        await compositeHeader.click();
      } else {
        await fallback.click();
      }
    });

    await test.step('operator sees sort=composite in the URL', async () => {
      await expect(page).toHaveURL(/sort=composite/);
    });
  });

  test('KEV-only toggle flips aria-pressed when clicked', async ({ page }) => {
    await test.step('operator navigates to /cves', async () => {
      await page.goto('/cves');
    });

    await test.step('operator reads the initial aria-pressed state', async () => {
      const toggle = page.locator(sel.kevOnlyToggle);
      await expect(toggle).toBeVisible();

      const initialPressed = await toggle.getAttribute('aria-pressed');
      const wasPressed = initialPressed === 'true';

      await test.step('operator clicks the KEV-only toggle', async () => {
        await toggle.click();
      });

      await test.step('operator confirms aria-pressed has flipped', async () => {
        const expectedAfter = wasPressed ? 'false' : 'true';
        await expect(toggle).toHaveAttribute('aria-pressed', expectedAfter);
      });
    });
  });

  test('empty-state or table container is present when there are no CVE data rows', async ({
    page,
  }) => {
    await test.step('operator navigates to /cves', async () => {
      await page.goto('/cves');
    });

    await test.step('operator checks whether the table has data rows', async () => {
      // A <table> or grid container must always be present regardless of data.
      const tableOrContainer = page
        .locator('table, [role="grid"], [role="table"]')
        .first();
      await expect(tableOrContainer).toBeVisible();

      // Count data rows (tbody tr or role=row excluding the header row).
      const rows = page.locator('tbody tr, [role="row"]:not([aria-rowindex="1"])');
      const rowCount = await rows.count();

      if (rowCount === 0) {
        // When the list is empty the page must show a non-empty-state message.
        // Accept any visible element that carries "no" / "empty" / "0 CVEs" semantics.
        const emptyIndicator = page.locator(
          '[data-testid*="empty"], [class*="empty"], :text("No CVEs"), :text("No results"), :text("No data")',
        );
        await expect(emptyIndicator.first()).toBeVisible();
      }
      // If rows are present the table renders correctly; assertion above covers it.
    });
  });
});
