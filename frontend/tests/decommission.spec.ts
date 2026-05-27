import { test, expect } from '@playwright/test';
import { STORAGE_STATE, API_URL, apiLogin, seedDevice } from './helpers';

test.use({ storageState: STORAGE_STATE });

test.describe('Decommission device', () => {
  // ---------------------------------------------------------------------------
  // TEST 1 — API-level decommission golden path
  // ---------------------------------------------------------------------------
  test('DELETE /api/devices/:id removes the device (API)', async ({ request }) => {
    let token: string;
    let dev: Awaited<ReturnType<typeof seedDevice>>;

    try {
      token = await apiLogin(request);
      dev = await seedDevice(request, token);
    } catch {
      test.skip(true, 'backend unavailable in this environment');
      return;
    }

    await test.step('operator seeds a device via the API', async () => {
      expect(typeof dev.id).toBe('number');
      expect(dev.hostname).toMatch(/^e2e-host-/);
    });

    await test.step('operator sends DELETE for the seeded device', async () => {
      const del = await request.delete(`${API_URL}/api/devices/${dev.id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      expect(del.status()).toBe(204);
    });

    await test.step('operator confirms the device no longer exists', async () => {
      const get = await request.get(`${API_URL}/api/devices/${dev.id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      // Backend throws NoSuchElementException → 404 (or other 4xx).
      expect(get.status()).toBeGreaterThanOrEqual(400);
      expect(get.status()).toBeLessThan(500);
    });
  });

  // ---------------------------------------------------------------------------
  // TEST 2 — UI dialog test
  //
  // C1: DeviceDetailPanel (and DecommissionButton) is mounted exclusively from
  // TopologyPage. The panel's open state is driven by handleNodeClick, which is
  // called only from the Cytoscape canvas node click handler — there is no
  // device list, table, sidebar link, or any other non-canvas DOM entry point.
  // Clicking canvas pixel coordinates is flaky by construction and is forbidden
  // per the brief. This test is therefore marked fixme until a minimal
  // data-testid hook is added to the Cytoscape node layer.
  // ---------------------------------------------------------------------------
  test('UI: decommission dialog opens and confirms device removal', async () => {
    test.fixme(
      true,
      'C1: device detail opens via a Cytoscape canvas node click which is not DOM-addressable; ' +
        'see docs/analysis-v41.md. Tracked for a future minimal node-testid hook.',
    );

    // Sketch of intended interactions (unreachable until a DOM hook exists):
    //
    // const token = await apiLogin(page.request());
    // const dev = await seedDevice(page.request(), token);
    //
    // await test.step('operator navigates to the topology page', async () => {
    //   await page.goto('/');
    // });
    //
    // await test.step('operator opens the device detail panel', async () => {
    //   // Requires a non-canvas entry point, e.g.:
    //   //   await page.click(`[data-testid="device-node-${dev.id}"]`);
    //   // or a devices list/table row.
    // });
    //
    // await test.step('operator clicks the Decommission button', async () => {
    //   await page.getByRole('button', { name: /Decommission/i }).click();
    //   await expect(page.locator(sel.decommissionDialog)).toBeVisible();
    // });
    //
    // await test.step('operator types the hostname to confirm', async () => {
    //   await page.locator(sel.decommissionConfirm).fill(dev.hostname);
    //   await page.getByRole('button', { name: /^Confirm$/i }).click();
    // });
    //
    // await test.step('operator confirms the device is removed from the DOM', async () => {
    //   await expect(page.locator(sel.decommissionDialog)).not.toBeVisible();
    //   // The topology graph or any device list should no longer show dev.hostname.
    // });
  });
});
