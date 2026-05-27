import type {
  ActiveCidr,
  AuditEntry, AuditFilters,
  ChangePasswordRequest,
  CreateUserRequest,
  Criticality, CveDetailDto, CveFleetSort, CveSummaryDto,
  Device, DeviceRiskDto, FeedsStatusDto, InitialSyncRequest, InitialSyncResponse,
  IntegrationConfigDto, IntegrationPushResponse, IntegrationType,
  InterfaceInfo, NetworkService,
  OtProbeRequest, OtProbeResponse,
  Page, PassiveDiscoveryRequest, PassiveDiscoveryResponse,
  Scan, ScanDetail, ScanPolicyCreateRequest, ScanPolicyDto, ScanRequest,
  ShortestPathResponse,
  SyncStatusResponse,
  TopRiskDeviceDto,
  UserDto, UserRole,
} from './types';
import { clearAuth, getToken } from '../hooks/useAuth';

const BASE = (import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080') as string;

/** HTTP statuses that warrant a single bounded retry. 5xx-transient only. */
const RETRYABLE_STATUSES: ReadonlySet<number> = new Set([502, 503, 504]);
/** Delay before the single retry attempt. ~750ms keeps the worst-case latency under 1.5s. */
const RETRY_BACKOFF_MS = 750;

/**
 * Single fetch attempt. Throws {@link Error} with the canonical
 * {@code `${status} ${statusText}`} message on non-OK responses (after the 401
 * side-effect). Network failures bubble up as the underlying {@link TypeError}.
 */
async function requestOnce<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    ...((init?.headers as Record<string, string>) ?? {}),
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const response = await fetch(`${BASE}${path}`, { ...init, headers });
  if (response.status === 401) {
    clearAuth();
    throw new Error('401 Unauthorized — please sign in again');
  }
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return (await response.json()) as T;
}

/**
 * Bounded-retry wrapper around {@link requestOnce}. Retries exactly once on:
 * <ul>
 *   <li>{@link TypeError} (browser surfaces network failures as TypeError).</li>
 *   <li>HTTP 502 / 503 / 504 — transient upstream / gateway / timeout responses.</li>
 * </ul>
 * Does NOT retry on 4xx (including 401 — the auth-clear side-effect has already
 * fired by the time the throw reaches us, and re-issuing the call would just
 * tear down auth a second time). Preserves the existing JWT-attach and
 * 401-clears-auth contract because both run inside {@link requestOnce}.
 */
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  try {
    return await requestOnce<T>(path, init);
  } catch (err) {
    if (!isRetryable(err)) throw err;
    await new Promise(resolve => setTimeout(resolve, RETRY_BACKOFF_MS));
    return await requestOnce<T>(path, init);
  }
}

/** True iff {@code err} is a {@link TypeError} (network) or an HTTP 502/503/504 Error. */
function isRetryable(err: unknown): boolean {
  if (err instanceof TypeError) return true;
  if (err instanceof Error) {
    // The status code lives at the start of the canonical error message
    // ({@code "503 Service Unavailable"}) — parse the leading integer and check
    // it against the allow-list. Cheaper than introducing an ApiError subclass.
    const match = /^(\d{3})\s/.exec(err.message);
    if (match) return RETRYABLE_STATUSES.has(Number(match[1]));
  }
  return false;
}

export interface DeviceUpdatePayload {
  hostname?: string | null;
  criticality?: Criticality;
}

export const api = {
  listDevices: () =>
    request<Page<Device>>('/api/devices?size=200'),
  getDevice: (id: number) =>
    request<Device>(`/api/devices/${id}`),
  updateDevice: (id: number, current: Device, patch: DeviceUpdatePayload) => {
    // PUT replaces the resource; merge patch over current to preserve required fields (e.g. ipAddress).
    const body: Record<string, unknown> = {
      ipAddress: current.ipAddress,
      hostname: current.hostname,
      macAddress: current.macAddress,
      firstSeen: current.firstSeen,
      lastSeen: current.lastSeen,
      criticality: current.criticality,
    };
    if (Object.prototype.hasOwnProperty.call(patch, 'hostname')) body.hostname = patch.hostname;
    if (patch.criticality !== undefined) body.criticality = patch.criticality;
    return request<Device>(`/api/devices/${id}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    });
  },
  deleteDevice: async (id: number): Promise<void> => {
    const token = getToken();
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(`${BASE}/api/devices/${id}`, { method: 'DELETE', headers });
    if (response.status === 401) {
      clearAuth();
      throw new Error('401 Unauthorized — please sign in again');
    }
    if (!response.ok && response.status !== 204) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
  },
  deviceRisk: (id: number) =>
    request<DeviceRiskDto>(`/api/risk/device/${id}`),
  deviceRisksBatch: async (ids: number[]): Promise<Map<number, DeviceRiskDto>> => {
    if (ids.length === 0) return new Map();
    const obj = await request<Record<number, DeviceRiskDto>>(
      `/api/risk/devices?ids=${ids.join(',')}`
    );
    const map = new Map<number, DeviceRiskDto>();
    for (const [k, v] of Object.entries(obj)) {
      map.set(Number(k), v);
    }
    return map;
  },
  topRisk: (n: number = 10) =>
    request<TopRiskDeviceDto[]>(`/api/risk/top?n=${n}`),
  cveDetail: (cveId: string) =>
    request<CveDetailDto>(`/api/cve/${encodeURIComponent(cveId)}`),
  /**
   * GET /api/cve/fleet — paginated CVE list. v3-F1 adds optional {@code kevOnly}
   * (narrows to KEV-catalog members) and {@code sort} (enrichment-window sort by
   * composite / kev / epss). When {@code sort} is omitted the backend returns the
   * stable default ordering of {@code cvssV31Score DESC, cveId ASC} — the frontend
   * opts into composite-DESC on first render via the UI default (Task 5).
   */
  listFleetCves: (
    page: number = 0,
    size: number = 20,
    minScore?: number,
    deviceId?: number,
    kevOnly?: boolean,
    sort?: CveFleetSort,
  ) => {
    const params = new URLSearchParams({ page: String(page), size: String(size) });
    if (minScore !== undefined) params.set('minScore', String(minScore));
    if (deviceId !== undefined) params.set('deviceId', String(deviceId));
    if (kevOnly === true) params.set('kevOnly', 'true');
    if (sort !== undefined) params.set('sort', sort);
    return request<Page<CveSummaryDto>>(`/api/cve/fleet?${params.toString()}`);
  },
  listServicesForDevice: (id: number) =>
    request<NetworkService[]>(`/api/services?deviceId=${id}`),
  triggerScan: async (req: ScanRequest): Promise<{ id: number }> => {
    const token = getToken();
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(`${BASE}/api/scan`, {
      method: 'POST',
      headers,
      body: JSON.stringify(req),
    });
    if (response.status === 401) {
      clearAuth();
      throw new Error('401 Unauthorized — please sign in again');
    }
    if (response.status === 400) {
      const body = await response.json().catch(() => null) as { error?: string; message?: string } | null;
      if (body?.error === 'scope_too_large') {
        throw new Error(`400 scope_too_large: ${body.message ?? 'scope too large'}`);
      }
      throw new Error(`400 ${body?.message ?? response.statusText}`);
    }
    if (response.status === 429) {
      const retryAfter = response.headers.get('Retry-After') ?? '60';
      throw new Error(`429 Rate limit exceeded — retry after ${retryAfter}s`);
    }
    if (!response.ok && response.status !== 202) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return (await response.json()) as { id: number };
  },
  getScanDetail: (id: number) =>
    request<ScanDetail>(`/api/scans/${id}`),
  listScans: (size = 10) =>
    request<Page<Scan>>(`/api/scans?size=${size}&sort=requestedAt,desc`),
  feedsStatus: () =>
    request<FeedsStatusDto>('/api/risk/feeds/status'),
  triggerInitialSync: (body?: InitialSyncRequest) =>
    request<InitialSyncResponse>('/api/admin/initial-sync', {
      method: 'POST',
      body: body ? JSON.stringify(body) : '{}',
    }),
  syncStatus: () =>
    request<SyncStatusResponse>('/api/admin/sync/status'),
  listAudit: (filters: AuditFilters) => {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') params.set(k, String(v));
    });
    if (!params.has('sort')) params.set('sort', 'occurredAt,desc');
    return request<Page<AuditEntry>>(`/api/audit?${params.toString()}`);
  },
  downloadAuditCsv: async (filters: AuditFilters): Promise<Blob> => {
    const token = getToken();
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '' && k !== 'page' && k !== 'size') {
        params.set(k, String(v));
      }
    });
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(`${BASE}/api/audit/csv?${params.toString()}`, { headers });
    if (response.status === 401) {
      clearAuth();
      throw new Error('401 Unauthorized — please sign in again');
    }
    if (response.status === 413) {
      const body = await response.json();
      throw new Error(`CSV cap exceeded: filteredCount=${body.filteredCount}, limit=${body.limit}`);
    }
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return await response.blob();
  },

  /** GET /api/discovery/interfaces — ADMIN-only. Returns [] on 403 to keep the form usable. */
  listInterfaces: async (): Promise<InterfaceInfo[]> => {
    try {
      return await request<InterfaceInfo[]>('/api/discovery/interfaces');
    } catch (err) {
      // VIEWER calls or transient errors should not blow up the panel; the caller
      // can fall back to a hardcoded interface list.
      if (err instanceof Error && err.message.startsWith('403')) return [];
      throw err;
    }
  },

  /**
   * GET /api/discovery/active-cidr — VIEWER and ADMIN.
   *
   * <p>Returns the documented empty shape on any error so the scan form
   * always has a usable fallback and never blocks submit.
   */
  getActiveCidr: async (): Promise<ActiveCidr> => {
    try {
      return await request<ActiveCidr>('/api/discovery/active-cidr');
    } catch {
      return { iface: null, cidr: null, ipAddress: null, prefix: 0 };
    }
  },

  /** POST /api/discovery/passive — ADMIN-only. */
  discoverPassive: (payload: PassiveDiscoveryRequest) =>
    request<PassiveDiscoveryResponse>('/api/discovery/passive', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /** POST /api/ot-probe — ADMIN-only. Read-only fingerprint; never writes to the target. */
  probeOt: (payload: OtProbeRequest) =>
    request<OtProbeResponse>('/api/ot-probe', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /**
   * POST /api/auth/change-password — authenticated. Returns 204 on success.
   *
   * <p>Throws {@code Error('429 ...')} when rate-limited (the panel surfaces the
   * Retry-After header to the user). Throws {@code Error('401 ...')} when the
   * old password is wrong. The new password is never logged.
   */
  changePassword: async (payload: ChangePasswordRequest): Promise<void> => {
    const token = getToken();
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(`${BASE}/api/auth/change-password`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });
    if (response.status === 204) return;
    if (response.status === 429) {
      const retryAfter = response.headers.get('Retry-After') ?? '60';
      throw new Error(`429 Too Many Requests — retry after ${retryAfter}s`);
    }
    if (response.status === 401) {
      // Distinct from generic 401 — don't blow the session away. The caller is
      // already authenticated; this 401 means the supplied {@code oldPassword}
      // didn't match.
      throw new Error('401 Old password incorrect');
    }
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
  },

  /** GET /api/users — ADMIN-only. Paginated. */
  listUsers: (page = 0, size = 50) =>
    request<Page<UserDto>>(`/api/users?page=${page}&size=${size}&sort=username,asc`),

  /** POST /api/users — ADMIN-only. Returns the created user (no password hash). */
  createUser: async (payload: CreateUserRequest): Promise<UserDto> => {
    const token = getToken();
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(`${BASE}/api/users`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });
    if (response.status === 401) {
      clearAuth();
      throw new Error('401 Unauthorized — please sign in again');
    }
    if (response.status === 409) {
      throw new Error('409 Username already exists');
    }
    if (!response.ok && response.status !== 201) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return (await response.json()) as UserDto;
  },

  /** PUT /api/users/{username}/role — ADMIN-only. */
  changeUserRole: (username: string, role: UserRole) =>
    request<UserDto>(`/api/users/${encodeURIComponent(username)}/role`, {
      method: 'PUT',
      body: JSON.stringify({ role }),
    }),

  /** GET /api/scan-policy — ADMIN-only. Paginated. */
  listScanPolicies: (page = 0, size = 50) =>
    request<Page<ScanPolicyDto>>(`/api/scan-policy?page=${page}&size=${size}&sort=createdAt,desc`),

  /** POST /api/scan-policy — ADMIN-only. Returns the created policy. */
  createScanPolicy: async (payload: ScanPolicyCreateRequest): Promise<ScanPolicyDto> => {
    const token = getToken();
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(`${BASE}/api/scan-policy`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });
    if (response.status === 401) {
      clearAuth();
      throw new Error('401 Unauthorized — please sign in again');
    }
    if (response.status === 400) {
      const body = await response.json().catch(() => null) as { error?: string; message?: string } | null;
      throw new Error(`400 ${body?.message ?? response.statusText}`);
    }
    if (response.status === 409) {
      throw new Error('409 A policy with that name already exists');
    }
    if (!response.ok && response.status !== 201) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return (await response.json()) as ScanPolicyDto;
  },

  /** PUT /api/scan-policy/{id}/disable — ADMIN-only. */
  disableScanPolicy: (id: number) =>
    request<ScanPolicyDto>(`/api/scan-policy/${id}/disable`, { method: 'PUT' }),

  /** PUT /api/scan-policy/{id}/enable — ADMIN-only. */
  enableScanPolicy: (id: number) =>
    request<ScanPolicyDto>(`/api/scan-policy/${id}/enable`, { method: 'PUT' }),

  /** DELETE /api/scan-policy/{id} — ADMIN-only. */
  deleteScanPolicy: async (id: number): Promise<void> => {
    const token = getToken();
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(`${BASE}/api/scan-policy/${id}`, { method: 'DELETE', headers });
    if (response.status === 401) {
      clearAuth();
      throw new Error('401 Unauthorized — please sign in again');
    }
    if (!response.ok && response.status !== 204) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
  },

  /**
   * GET /api/graph/shortest-path?from=N&to=N — VIEWER or ADMIN.
   *
   * <p>Backend computes the lowest-cost attack path via JGraphT over the
   * Castellum attack graph. Returns {@code pathFound: false} with an empty
   * {@code hops} array when the two devices are not reachable.
   */
  shortestPath: (params: { from: number; to: number }) =>
    request<ShortestPathResponse>(
      `/api/graph/shortest-path?from=${params.from}&to=${params.to}`
    ),

  /**
   * POST /api/threat-intel/export — ADMIN-only. Streams a STIX 2.1 JSON
   * bundle as a {@link Blob} suitable for download via an anchor element.
   */
  exportStixBundle: async (): Promise<Blob> => {
    const token = getToken();
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(`${BASE}/api/threat-intel/export`, {
      method: 'POST',
      headers,
    });
    if (response.status === 401) {
      clearAuth();
      throw new Error('401 Unauthorized — please sign in again');
    }
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return await response.blob();
  },

  /** GET /api/integrations/{type} — ADMIN-only. Throws {@code Error('404 ...')} when not configured. */
  getIntegrationConfig: (type: IntegrationType) =>
    request<IntegrationConfigDto>(`/api/integrations/${type}`),

  /**
   * PUT /api/integrations/{type} — ADMIN-only. {@code config} is non-secret JSON;
   * {@code credentials} is encrypted server-side via AES-256-GCM.
   */
  saveIntegrationConfig: (
    type: IntegrationType,
    payload: { config: Record<string, unknown>; credentials: string },
  ) =>
    request<IntegrationConfigDto>(`/api/integrations/${type}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  /** POST /api/integrations/{type}/push — ADMIN-only. Returns push outcome + timestamp. */
  pushIntegration: (type: IntegrationType) =>
    request<IntegrationPushResponse>(`/api/integrations/${type}/push`, {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  /** POST /api/users/{username}/disable — ADMIN-only. */
  disableUser: async (username: string): Promise<void> => {
    const token = getToken();
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(
      `${BASE}/api/users/${encodeURIComponent(username)}/disable`,
      { method: 'POST', headers }
    );
    if (response.status === 401) {
      clearAuth();
      throw new Error('401 Unauthorized — please sign in again');
    }
    if (!response.ok && response.status !== 204) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
  },
};
