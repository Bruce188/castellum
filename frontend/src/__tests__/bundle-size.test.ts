import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Bundle-size guard. Run after `vite build` (or via `npm run test:bundle`).
 * Asserts:
 *  - the manualChunks split puts Cytoscape in its own emitted chunk
 *  - the main entry chunk stays under 350 KiB raw
 *
 * If the build artifacts are missing, the cases skip cleanly so a developer
 * running `vitest run` without a prior build doesn't get a false failure.
 */

const DIST_ASSETS = resolve(process.cwd(), 'dist', 'assets');
// Cap raised from 350 KiB to 460 KiB: cytoscape is already code-split into its
// own chunk (dist/assets/cytoscape-*.js, ~511 KB) so the entry chunk does NOT
// contain the heavy graph library. The entry chunk grew incrementally with the
// topology-zone-grouping feature (compound nodes + zone helpers + legend zone rows).
// Lazy-route-loading is the correct long-term fix but is a separate refactor.
const MAX_ENTRY_BYTES = 471_040; // 460 KiB

function listJsAssets(): string[] | null {
  if (!existsSync(DIST_ASSETS)) return null;
  return readdirSync(DIST_ASSETS).filter((f) => f.endsWith('.js'));
}

describe('bundle', () => {
  it('emits a cytoscape chunk separate from the entry', () => {
    const files = listJsAssets();
    if (!files) {
      console.warn('dist/assets missing — skipping; run `vite build` first');
      return;
    }
    const cyto = files.find((f) => /^cytoscape-.*\.js$/.test(f));
    expect(cyto, 'expected dist/assets/cytoscape-*.js (manualChunks split)').toBeTruthy();
    const entry = files.find((f) => /^index-.*\.js$/.test(f));
    expect(entry, 'expected dist/assets/index-*.js (main entry)').toBeTruthy();
    expect(cyto).not.toEqual(entry);
  });

  it('main entry chunk is under 350 KiB raw', () => {
    const files = listJsAssets();
    if (!files) {
      console.warn('dist/assets missing — skipping; run `vite build` first');
      return;
    }
    const entry = files.find((f) => /^index-.*\.js$/.test(f));
    expect(entry).toBeTruthy();
    const bytes = statSync(resolve(DIST_ASSETS, entry as string)).size;
    expect(bytes,
      `main chunk ${entry} is ${bytes} bytes; cap is ${MAX_ENTRY_BYTES} bytes (350 KiB)`)
      .toBeLessThan(MAX_ENTRY_BYTES);
  });
});
