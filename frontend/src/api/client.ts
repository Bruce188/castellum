import type {
  Device, DeviceRiskDto, FeedsStatusDto, InitialSyncRequest, InitialSyncResponse,
  NetworkService, Page, Scan, ScanRequest,
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

export const api = {
  listDevices: () =>
    request<Page<Device>>('/api/devices?size=200'),
  deviceRisk: (id: number) =>
    request<DeviceRiskDto>(`/api/risk/device/${id}`),
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
};
