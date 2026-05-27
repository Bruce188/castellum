import { test, expect } from '@playwright/test';
import { sel, STORAGE_STATE } from './helpers';

test.use({ storageState: STORAGE_STATE });

test.describe('CVE + KEV + EPSS + Composite', () => {
  test('column headers are visible on the CVE list page', async ({ page }) => {
    await test.step('operator navigates to /cves', async () => {
      await page.goto('/cves');
    });

    await test.step('operator sees key column headers', async () => {
      // Scope to <th> column headers. A bare getByText('KEV') also matches the
      // "KEV only" filter toggle, which trips Playwright strict mode; the
      // columnheader role resolves each header unambiguously.
      await expect(
        page.getByRole('columnheader', { name: 'CVE ID' }).first(),
      ).toBeVisible();
      await expect(
        page.getByRole('columnheader', { name: 'CVSS v3.1' }).first(),
      ).toBeVisible();
      await expect(
        page.getByRole('columnheader', { name: 'KEV' }).first(),
      ).toBeVisible();
      await expect(
        page.getByRole('columnheader', { name: 'EPSS' }).first(),
      ).toBeVisible();
      await expect(
        page.getByRole('columnheader', { name: 'Composite' }).first(),
      ).toBeVisible();
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
      await expect(compositeHeader).toBeVisible();
      await compositeHeader.click();
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

      // Count data rows. Scope to tbody tr only — most tables do not set
      // aria-rowindex, so an aria-rowindex exclusion would let the header row
      // count as data.
      const rows = page.locator('tbody tr');
      const rowCount = await rows.count();

      if (rowCount === 0) {
        // When the list is empty the page must show an empty-state message.
        const emptyIndicator = page.getByText(/no (cves|results|data)/i);
        await expect(emptyIndicator.first()).toBeVisible();
      }
      // If rows are present the table renders correctly; assertion above covers it.
    });
  });
});
