import type { APIRequestContext } from '@playwright/test';

/** Frontend dev server origin (Playwright baseURL). */
export const BASE_URL = process.env.E2E_BASE_URL ?? 'http://127.0.0.1:5173';

/** Backend origin. NB: real port is 8081, not the Login.tsx 8080 default. */
export const API_URL = process.env.E2E_API_URL ?? 'http://localhost:8081';

/** Bootstrap admin credentials (overridable via env for CI). */
export const CREDS = {
  username: process.env.E2E_ADMIN_USERNAME ?? 'admin',
  password: process.env.E2E_ADMIN_PASSWORD ?? 'admin12345',
};

/** Where auth.setup persists the admin storage state. */
export const STORAGE_STATE = 'playwright/.auth/admin.json';

/** Verified selectors (see docs/analysis-v41.md § Grounding). */
export const sel = {
  loginUser: 'input[autocomplete="username"]',
  loginPass: 'input[autocomplete="current-password"]',
  loginSubmit: 'button[type="submit"]',
  jwtKey: 'castellum.jwt',
  topologyCanvas: '[data-testid="topology-canvas"]',
  topologyLegend: '[data-testid="topology-legend"]',
  kevOnlyToggle: '[data-testid="kev-only-toggle"]',
  kevBadge: '[data-testid="kev-badge"]',
  threatsDashboard: '[data-testid="threats-dashboard"]',
  threatsRowPrefix: '[data-testid^="threats-row-"]',
  relatedCvesPanelPrefix: '[data-testid^="related-cves-panel-"]',
  relatedCvesEmpty: '[data-testid="related-cves-empty"]',
  scanStatus: '[data-testid="scan-status"]',
  scanDetailNotFound: '[data-testid="scan-detail-not-found"]',
  decommissionDialog: '[data-testid="decommission-dialog"]',
  decommissionConfirm: 'input[aria-label="Type hostname to confirm"]',
} as const;

/** POST /api/auth/login and return the bearer token. */
export async function apiLogin(
  request: APIRequestContext,
  creds: { username: string; password: string } = CREDS,
): Promise<string> {
  const res = await request.post(`${API_URL}/api/auth/login`, {
    data: { username: creds.username, password: creds.password },
  });
  if (!res.ok()) {
    throw new Error(`apiLogin failed: ${res.status()} ${await res.text()}`);
  }
  const body = (await res.json()) as { token: string };
  if (!body.token) throw new Error('apiLogin: response missing token');
  return body.token;
}

export interface SeededDevice {
  id: number;
  ipAddress: string;
  hostname: string;
  discoveryScope: string;
}

/**
 * POST /api/devices (ADMIN) with a minimal valid body. ipAddress is unique by
 * constraint, so a per-call random octet pair avoids collisions across runs.
 */
export async function seedDevice(
  request: APIRequestContext,
  token: string,
  overrides: Partial<SeededDevice> = {},
): Promise<SeededDevice> {
  const rand = () => Math.floor(Math.random() * 254) + 1;
  const body = {
    ipAddress: overrides.ipAddress ?? `10.99.${rand()}.${rand()}`,
    hostname: overrides.hostname ?? `e2e-host-${Date.now()}`,
    discoveryScope: overrides.discoveryScope ?? 'HOME',
  };
  const res = await request.post(`${API_URL}/api/devices`, {
    headers: { Authorization: `Bearer ${token}` },
    data: body,
  });
  if (!res.ok()) {
    throw new Error(`seedDevice failed: ${res.status()} ${await res.text()}`);
  }
  return (await res.json()) as SeededDevice;
}

/** POST /api/scan (ADMIN) and return the created scan id. */
export async function triggerScan(
  request: APIRequestContext,
  token: string,
  cidr = '192.168.1.0/24',
): Promise<string> {
  const res = await request.post(`${API_URL}/api/scan`, {
    headers: { Authorization: `Bearer ${token}` },
    data: { cidr },
  });
  if (!res.ok()) {
    throw new Error(`triggerScan failed: ${res.status()} ${await res.text()}`);
  }
  const body = (await res.json()) as { id: string | number };
  return String(body.id);
}
