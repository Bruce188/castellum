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

export interface FeedsStatusDto {
  epss: {
    scoreDate: string | null;
    rowCount: number;
  };
  kev: {
    lastIngestedAt: string | null;
    entryCount: number;
  };
  nvd: {
    lastModified: string | null;
    rowCount: number;
  };
}

export interface InitialSyncRequest {
  since?: string;
  until?: string;
}

export interface InitialSyncResponse {
  status: 'started' | 'already-running';
  startedAt: string;
}

export interface AuditEntry {
  id: number;
  occurredAt: string;        // ISO8601
  actor: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  payload: string | null;    // serialized JSON string
}

export interface AuditFilters {
  since?: string;            // ISO8601
  until?: string;
  action?: string;
  actor?: string;
  resourceType?: string;
  page?: number;
  size?: number;             // clamped server-side to 500
}
