import { test, expect } from '@playwright/test';
import { sel, STORAGE_STATE } from './helpers';

test.use({ storageState: STORAGE_STATE });

test.describe('Threat intel + linked CVEs', () => {
  test('threats dashboard is visible', async ({ page }) => {
    await test.step('operator navigates to /threats', async () => {
      await page.goto('/threats');
    });

    await test.step('operator sees the threats dashboard container', async () => {
      await expect(page.locator(sel.threatsDashboard)).toBeVisible();
    });
  });

  test('expanding a device row reveals its linked-CVE panel', async ({ page }) => {
    await test.step('operator navigates to /threats', async () => {
      await page.goto('/threats');
      await expect(page.locator(sel.threatsDashboard)).toBeVisible();
    });

    const rows = page.locator(sel.threatsRowPrefix);

    await test.step('operator checks that at least one device row is rendered', async () => {
      const count = await rows.count();
      test.skip(count === 0, 'no threat rows seeded in this environment');
    });

    await test.step('operator clicks the first device row', async () => {
      await rows.first().click();
    });

    await test.step('operator sees the related-CVEs panel appear for that device', async () => {
      await expect(page.locator(sel.relatedCvesPanelPrefix).first()).toBeVisible();
    });
  });

  test('a device with no linked CVEs shows the empty state inside its panel', async ({ page }) => {
    await test.step('operator navigates to /threats', async () => {
      await page.goto('/threats');
      await expect(page.locator(sel.threatsDashboard)).toBeVisible();
    });

    const rows = page.locator(sel.threatsRowPrefix);

    await test.step('operator checks that at least one device row exists', async () => {
      const count = await rows.count();
      test.skip(count === 0, 'no threat rows seeded in this environment');
    });

    // Expand every row to find one whose panel contains the empty-state element.
    // We cannot know upfront which device has zero CVEs, so we probe each in turn.
    let foundEmptyPanel = false;

    await test.step('operator expands each row looking for a no-CVEs device', async () => {
      const count = await rows.count();
      for (let i = 0; i < count; i++) {
        await rows.nth(i).click();
        const panel = page.locator(sel.relatedCvesPanelPrefix).nth(i);
        const appeared = await panel.waitFor({ state: 'visible', timeout: 5000 }).then(() => true).catch(() => false);
        if (!appeared) {
          // Panel did not render for this row — collapse and try next.
          await rows.nth(i).click().catch(() => undefined);
          continue;
        }
        const emptyState = panel.locator(sel.relatedCvesEmpty);
        const hasEmpty = await emptyState.count() > 0;
        if (hasEmpty) {
          foundEmptyPanel = true;
          break;
        }
        // Collapse before moving to the next row so the UI stays predictable.
        await rows.nth(i).click().catch(() => undefined);
      }
    });

    await test.step('operator confirms a no-CVEs empty-state was found', async () => {
      test.skip(!foundEmptyPanel, 'no device with zero linked CVEs found in this environment');
      await expect(page.locator(sel.relatedCvesEmpty).first()).toBeVisible();
    });
  });
});
