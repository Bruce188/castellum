import { test, expect, type Page } from '@playwright/test';

const APP = 'http://127.0.0.1:5173';
const ADMIN = { username: 'admin', password: 'admin' };
const VIEWER = { username: 'viewer', password: 'admin' };

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

test.describe('EmptyCorpusBanner — banner → click → poll → dismiss', () => {
  test('admin sees banner and sync button; clicking switches to Syncing…; banner dismisses after poll', async ({ page }) => {
    // Stub the backend feeds/status to return all-zero on first call, then non-zero on second.
    let feedsCallCount = 0;
    await page.route('**/api/risk/feeds/status', route => {
      feedsCallCount += 1;
      const body = feedsCallCount === 1
        ? JSON.stringify({
            epss: { scoreDate: null, rowCount: 0 },
            kev: { lastIngestedAt: null, entryCount: 0 },
            nvd: { lastModified: null, rowCount: 0 },
          })
        : JSON.stringify({
            epss: { scoreDate: '2025-01-01', rowCount: 1000 },
            kev: { lastIngestedAt: '2025-01-01T00:00:00Z', entryCount: 100 },
            nvd: { lastModified: '2025-01-01T00:00:00Z', rowCount: 200000 },
          });
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body,
      });
    });

    // Stub the initial-sync endpoint
    await page.route('**/api/admin/initial-sync', route => {
      route.fulfill({
        status: 202,
        contentType: 'application/json',
        body: JSON.stringify({ status: 'started', startedAt: new Date().toISOString() }),
      });
    });

    await signIn(page, ADMIN);

    // Banner should be visible
    await expect(page.getByText(/Threat intelligence feeds are empty/i)).toBeVisible({ timeout: 8000 });

    // "Sync" button visible
    const syncBtn = page.getByRole('button', { name: /Sync NVD/i });
    await expect(syncBtn).toBeVisible();

    // Click the button
    await syncBtn.click();

    // Button should switch to "Syncing…" (disabled)
    await expect(page.getByRole('button', { name: /Syncing/i })).toBeDisabled({ timeout: 3000 });

    // Wait for the next polling tick (11s) — the second feeds/status call returns non-zero
    await page.waitForTimeout(11_000);

    // Banner should dismiss
    await expect(page.getByText(/Threat intelligence feeds are empty/i)).toHaveCount(0, { timeout: 5000 });
  });

  test('viewer sees banner but no sync button', async ({ page }) => {
    await page.route('**/api/risk/feeds/status', route => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          epss: { scoreDate: null, rowCount: 0 },
          kev: { lastIngestedAt: null, entryCount: 0 },
          nvd: { lastModified: null, rowCount: 0 },
        }),
      });
    });

    await signIn(page, VIEWER);

    await expect(page.getByText(/Threat intelligence feeds are empty/i)).toBeVisible({ timeout: 8000 });
    await expect(page.getByRole('button', { name: /Sync NVD/i })).toHaveCount(0);
  });
});
