import type {
  Device, DeviceRiskDto, NetworkService, Page, Scan, ScanRequest,
} from './types';

const BASE = (import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080') as string;

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    headers: { 'content-type': 'application/json' },
    ...init,
  });
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
};
