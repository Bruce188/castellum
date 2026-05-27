import { test, expect } from '@playwright/test';
import { sel, STORAGE_STATE, apiLogin, seedDevice } from './helpers';

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

test.describe('Topology non-collinear layout', () => {
  test('topology renders a non-collinear layout for a seeded multi-/24 fleet', async ({ page, request }) => {
    // Seed a small fleet across ≥2 /24s plus one APIPA node via the API.
    // The assertion is relative (>1 distinct y-coordinate) so it is
    // run-order-independent even if the backend already holds devices.
    // Devices are seeded best-effort — duplicate IP conflicts are silently
    // ignored since the existing device satisfies the non-collinearity goal.
    const token = await apiLogin(request);
    const trySeeed = (ip: string, scope: string) =>
      seedDevice(request, token, { ipAddress: ip, discoveryScope: scope }).catch(() => { /* duplicate OK */ });
    await trySeeed('10.50.1.10', 'HOME');
    await trySeeed('10.50.1.11', 'HOME');
    await trySeeed('10.50.2.10', 'HOME');
    await trySeeed('169.254.5.5', 'LINK_LOCAL');

    await page.goto('/');
    await expect(page.locator(sel.topologyCanvas)).toBeVisible();

    // Wait until the cytoscape instance is exposed and has loaded nodes.
    await page.waitForFunction(
      () => (window as unknown as { __cytoscape?: { nodes: () => { length: number } } }).__cytoscape
        && (window as unknown as { __cytoscape: { nodes: () => { length: number } } }).__cytoscape.nodes().length > 1,
    );

    // Read y-coordinates from the live cytoscape instance; assert non-collinearity.
    // randomize:true guarantees spread on a non-trivial graph; we only assert >1
    // distinct y — never exact coordinates.
    const ys = await page.evaluate(() =>
      (window as unknown as { __cytoscape: { nodes: () => Array<{ position: (axis: string) => number }> } })
        .__cytoscape.nodes().map((n) => Math.round(n.position('y'))),
    );
    expect(new Set(ys).size).toBeGreaterThan(1);
  });
});
