import type {
  AuditEntry, AuditFilters,
  Criticality, CveDetailDto,
  Device, DeviceRiskDto, FeedsStatusDto, InitialSyncRequest, InitialSyncResponse,
  InterfaceInfo, NetworkService,
  OtProbeRequest, OtProbeResponse,
  Page, PassiveDiscoveryRequest, PassiveDiscoveryResponse,
  Scan, ScanRequest, TopRiskDeviceDto,
} from './types';
import { clearAuth, getToken } from '../hooks/useAuth';

const BASE = (import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080') as string;

async function request<T>(path: string, init?: RequestInit): Promise<T> {
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

export interface DeviceUpdatePayload {
  hostname?: string | null;
  criticality?: Criticality;
}

export const api = {
  listDevices: () =>
    request<Page<Device>>('/api/devices?size=200'),
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
  topRisk: (n: number = 10) =>
    request<TopRiskDeviceDto[]>(`/api/risk/top?n=${n}`),
  cveDetail: (cveId: string) =>
    request<CveDetailDto>(`/api/cve/${encodeURIComponent(cveId)}`),
  listServicesForDevice: (id: number) =>
    request<NetworkService[]>(`/api/services?deviceId=${id}`),
  triggerScan: (req: ScanRequest) =>
    request<{ id: number }>('/api/scan', { method: 'POST', body: JSON.stringify(req) }),
  getScan: (id: number) =>
    request<Scan>(`/api/scans/${id}`),
  listScans: (size = 10) =>
    request<Page<Scan>>(`/api/scans?size=${size}&sort=requestedAt,desc`),
  feedsStatus: () =>
    request<FeedsStatusDto>('/api/risk/feeds/status'),
  triggerInitialSync: (body?: InitialSyncRequest) =>
    request<InitialSyncResponse>('/api/admin/initial-sync', {
      method: 'POST',
      body: body ? JSON.stringify(body) : '{}',
    }),
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
};
