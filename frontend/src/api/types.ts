export type Criticality = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ScanType = 'PING_SWEEP' | 'SERVICE_DETECT' | 'OS_FINGERPRINT';
export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETE' | 'FAILED';
export type RiskTier = 'low' | 'med' | 'high' | 'crit' | 'unknown';

export interface Device {
  id: number;
  ipAddress: string;
  hostname: string | null;
  macAddress: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
  criticality: Criticality;
}

export interface NetworkService {
  id: number;
  deviceId: number;
  port: number;
  protocol: string;
  name: string | null;
  version: string | null;
  observedAt: string | null;
  vendor: string | null;
  product: string | null;
  protocolFamily: string | null;
}

/** Backend BigDecimal serializes as string by default. Callers convert via Number(score). */
export interface DeviceRiskDto {
  deviceId: number;
  score: string;
  topCveIds: string[];
}

export interface Page<T> {
  content: T[];
  totalElements: number;
  totalPages: number;
  number: number;
  size: number;
}

export interface Scan {
  id: number;
  cidr: string;
  scanType: ScanType;
  status: ScanStatus;
  requestedAt: string;
  completedAt: string | null;
  failureReason?: string | null;
}

export interface ScanRequest {
  cidr: string;
  type: ScanType;
}
