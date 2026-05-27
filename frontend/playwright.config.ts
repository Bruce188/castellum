import { defineConfig, devices } from '@playwright/test';

const BASE_URL = process.env.E2E_BASE_URL ?? 'http://127.0.0.1:5173';
const API_URL = process.env.E2E_API_URL ?? 'http://localhost:8081';

export default defineConfig({
  testDir: './tests',
  timeout: 30000,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  // The dev server is the frontend only. The backend (:8081) is assumed to be
  // already running locally; CI boots it as a separate step. VITE_API_BASE_URL
  // is injected because Login.tsx defaults to :8080, which is not the real port.
  webServer: {
    command: 'npm run dev',
    url: BASE_URL,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: { VITE_API_BASE_URL: API_URL },
  },
  projects: [
    { name: 'setup', testMatch: /auth\.setup\.ts/ },
    {
      // New E2E specs opt into admin storage state per-file via
      // `test.use({ storageState: STORAGE_STATE })`. Storage state is NOT set
      // globally here: the pre-existing self-login specs (audit-log,
      // initial-sync-banner, qa-sweep) navigate to an unauthenticated app and
      // would break if every context arrived already authenticated.
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
      dependencies: ['setup'],
    },
  ],
});
