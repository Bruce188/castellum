import { test, expect, type Page } from '@playwright/test';
import { STORAGE_STATE } from './helpers';

test.use({ storageState: STORAGE_STATE });

/**
 * Dev-console guard for ordinary operator work: no uncaught exceptions
 * (`pageerror`) and no `console.error` output across the core authenticated
 * routes and the CVE list → detail → pagination flow.
 *
 * `console.warn`, failed requests, and 4xx/5xx responses are collected and
 * printed for triage but NOT asserted — yellow warnings and (possibly expected)
 * non-2xx responses are surfaced, while only hard errors gate the test.
 */

interface Captured {
  kind: string;
  text: string;
  location?: string;
}

function attach(page: Page, sink: Captured[]): void {
  page.on('pageerror', (err) => {
    sink.push({ kind: 'pageerror', text: `${err.name}: ${err.message}` });
  });
  page.on('console', (msg) => {
    const type = msg.type();
    if (type === 'error' || type === 'warning') {
      const loc = msg.location();
      sink.push({
        kind: type,
        text: msg.text(),
        location: loc?.url ? `${loc.url}:${loc.lineNumber}` : undefined,
      });
    }
  });
  page.on('requestfailed', (req) => {
    sink.push({
      kind: 'requestfailed',
      text: `${req.method()} ${req.url()} — ${req.failure()?.errorText ?? 'failed'}`,
    });
  });
  page.on('response', (resp) => {
    if (resp.status() >= 400) {
      sink.push({ kind: `http${resp.status()}`, text: `${resp.request().method()} ${resp.url()}` });
    }
  });
}

function report(label: string, sink: Captured[]): void {
  if (sink.length === 0) {
    console.log(`[console-errors] ${label} — clean`);
    return;
  }
  console.log(`\n[console-errors] ${label} — ${sink.length} issue(s):`);
  for (const c of sink) {
    console.log(`  · [${c.kind}] ${c.text}${c.location ? '  @ ' + c.location : ''}`);
  }
}

// A failed integration-health probe (e.g. POST /api/integrations/MISP/probe) reflects an
// external dependency / deployment state — the integration being unreachable — NOT an app
// defect. The browser logs the failed request as a console error regardless; surface it in
// the report but do not let it gate the run.
const isExpectedIntegrationProbe = (c: Captured): boolean =>
  /\/api\/integrations\/[^/]+\/probe/.test(c.text) || (c.location ?? '').includes('/api/integrations/');

/** Hard errors gate the test; warnings, non-2xx, and integration-probe failures are report-only. */
const hardErrors = (sink: Captured[]): Captured[] =>
  sink
    .filter((c) => c.kind === 'pageerror' || c.kind === 'error')
    .filter((c) => !isExpectedIntegrationProbe(c));

const settle = (page: Page) =>
  page.waitForLoadState('networkidle', { timeout: 4000 }).catch(() => {});

test('no console errors during CVE list → detail → pagination flow', async ({ page }) => {
  const sink: Captured[] = [];
  attach(page, sink);

  await page.goto('/cves');
  await expect(page.getByRole('columnheader', { name: 'CVE ID' }).first()).toBeVisible();
  await settle(page);

  // Open the first CVE detail (when rows exist), then close it.
  const firstRow = page.getByRole('button', { name: /View details for/ }).first();
  if ((await firstRow.count()) > 0 && (await firstRow.isVisible().catch(() => false))) {
    await firstRow.click();
    await expect(page.getByTestId('cve-detail-panel')).toBeVisible();
    await settle(page);
    await page.getByLabel('Close CVE panel').click();
  }

  // Paginate forward + back when a second page exists.
  const next = page.getByRole('button', { name: 'Next' });
  if ((await next.count()) > 0 && (await next.isEnabled().catch(() => false))) {
    await next.click();
    await settle(page);
    const prev = page.getByRole('button', { name: 'Prev' });
    if (await prev.isEnabled().catch(() => false)) {
      await prev.click();
      await settle(page);
    }
  }

  // Severity / KEV toggles drive re-fetch paths.
  await page.getByTestId('kev-only-toggle').click();
  await settle(page);

  report('cve-flow', sink);
  const hard = hardErrors(sink);
  expect(hard, `console errors during CVE flow:\n${hard.map((c) => c.text).join('\n')}`).toEqual([]);
});

test('no console errors navigating core authenticated routes', async ({ page }) => {
  const sink: Captured[] = [];
  attach(page, sink);

  for (const path of ['/', '/scans', '/threats', '/cves', '/attack-graph', '/audit', '/settings']) {
    await page.goto(path);
    await settle(page);
    await page.waitForTimeout(400); // flush late async renders
  }

  report('core-routes', sink);
  const hard = hardErrors(sink);
  expect(hard, `console errors across routes:\n${hard.map((c) => `${c.kind}: ${c.text}`).join('\n')}`).toEqual([]);
});
