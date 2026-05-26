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
  /** Optional component breakdown used by the "why this score?" UI. Absent on legacy responses. */
  components?: ScoreComponents | null;
}

/** Breakdown of a device's composite risk score into its input components. */
export interface ScoreComponents {
  /** CVSS base score on the 0-10 scale (max across the device's matched CVEs). */
  cvssMax: string;
  /** EPSS exploit-probability score in [0.00, 1.00] (max across matched CVEs). */
  epssMax: string;
  /** True if any matched CVE appears in CISA's KEV catalog. */
  kevPresent: boolean;
  /** Criticality weight: LOW=0.00, MEDIUM=0.25, HIGH=0.50, CRITICAL=1.00. */
  criticalityWeight: string;
}

/** Read-only DTO returned by GET /api/risk/top — fleet-ranked risk leaderboard. */
export interface TopRiskDeviceDto {
  deviceId: number;
  hostname: string | null;
  ipAddress: string;
  criticality: Criticality;
  score: string;
  kevCount: number;
}

/** Read-only DTO returned by GET /api/cve/{cveId}. Includes the upstream NVD rawJson. */
export interface CveDetailDto {
  cveId: string;
  published: string | null;
  lastModified: string;
  vulnStatus: string | null;
  description: string | null;
  cvssV31Score: string | null;
  cvssV31Vector: string | null;
  cvssV30Score: string | null;
  cvssV30Vector: string | null;
  cvssV2Score: string | null;
  cvssV2Vector: string | null;
  fetchedAt: string | null;
  rawJson: string | null;
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
  retryCount?: number;
}

export interface ScanRequest {
  cidr: string;
  type: ScanType;
}

export interface ScanPolicyDto {
  id: number;
  name: string;
  cronExpression: string;
  cidr: string;
  scanType: ScanType;
  enabled: boolean;
  createdAt: string;
  lastTriggeredAt: string | null;
}

export interface ScanPolicyCreateRequest {
  name: string;
  cronExpression: string;
  cidr: string;
  scanType: ScanType;
  enabled?: boolean;
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

// ----- Discovery (passive) -----

/** Passive-discovery sources understood by the backend enum {@code DiscoverySource}. */
export type DiscoverySource = 'ARP' | 'MDNS' | 'PCAP' | 'LLDP' | 'CDP';

export interface PassiveDiscoveryRequest {
  iface: string;
  /** 0 means "use the backend default of 30 seconds"; bounded 0..300 on the server. */
  durationSeconds: number;
  sources: DiscoverySource[];
}

export interface PassiveDiscoveryResponse {
  discovered: number;
  deviceIds: number[];
  /** Map of source name → count of neighbors discovered via that source. */
  perSourceCount: Record<DiscoverySource, number>;
  sweepId: number | null;
}

/** GET /api/discovery/interfaces — host-visible up, non-loopback NICs. */
export interface InterfaceInfo {
  name: string;
  displayName: string;
  mtu: number;
}

// ----- OT probe -----

/** Matches {@code io.castellum.ot.OtProtocol} enum names. */
export type OtProtocol = 'MODBUS_TCP' | 'DNP3' | 'S7COMM' | 'BACNET_IP';

export interface OtProbeRequest {
  host: string;
  port: number;
  protocol: OtProtocol;
}

export interface OtProbeResponse {
  host: string;
  port: number;
  protocol: OtProtocol;
  vendor: string | null;
  product: string | null;
  version: string | null;
  /** Protocol-native decoded fields; Modbus uses numeric-string keys ("0", "1"). */
  rawFields: Record<string, string>;
  deviceId: number;
  serviceId: number;
  observedAt: string;
}

/** Mirror of the backend {@code Role} enum. */
export type UserRole = 'ADMIN' | 'VIEWER';

/** Login response payload. {@code mustChangePassword} signals first-login rotation. */
export interface LoginResult {
  token: string;
  expiresAt: string;
  roles: string[];
  mustChangePassword: boolean;
}

/** Read-only projection of a managed user. {@code passwordHash} is never returned. */
export interface UserDto {
  id: number;
  username: string;
  role: UserRole;
  enabled: boolean;
  createdAt: string | null;
  lastLoginAt: string | null;
}

export interface CreateUserRequest {
  username: string;
  role: UserRole;
  initialPassword: string;
}

export interface ChangePasswordRequest {
  oldPassword: string;
  newPassword: string;
}
