export type Criticality = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ScanType = 'PING_SWEEP' | 'SERVICE_DETECT' | 'OS_FINGERPRINT';
export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETE' | 'FAILED';
export type RiskTier = 'low' | 'med' | 'high' | 'crit' | 'unknown';
export type DiscoveryScope = 'HOME' | 'DOCKER_BRIDGE' | 'LINK_LOCAL' | 'LOOPBACK' | 'PUBLIC';
/** Mirrors the backend {@code io.castellum.discovery.DeviceRole} enum. */
export type DeviceRole = 'LAPTOP' | 'DESKTOP' | 'SERVER' | 'ROUTER' | 'CONTAINER' | 'UNKNOWN';

export interface Device {
  id: number;
  ipAddress: string;
  hostname: string | null;
  macAddress: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
  criticality: Criticality;
  discoveryScope: DiscoveryScope;
  /**
   * Most recent network interface name (from the host running Castellum) that
   * observed this device's MAC in an ARP table — populated by ARP rescan, never
   * by NMAP/OT rescan. Null when the device has never been ARP-observed
   * (typical for NMAP-only seeded rows or devices on segments Castellum does
   * not span). Surfaces in {@link DeviceDetailPanel} as a hint for which
   * physical or virtual network bound the device.
   */
  lastSeenIface: string | null;
  /**
   * Most recent discovery source that observed this device.
   * Last-writer-wins on every upsert (mirrors {@code lastSeen}).
   * Null for devices seeded before V19 migration.
   */
  discoverySource: DiscoverySource | null;
  /** Count of network services observed on this device (from GET /api/devices serviceCount). */
  serviceCount: number;
  /** nmap -O OS-fingerprint match name (e.g. "Linux 5.4 - 5.15"); null until an OS scan matches. */
  osName: string | null;
  /** OS-match confidence 0-100 from nmap's osmatch accuracy; null when no match. */
  osAccuracy: number | null;
  /** Optional raw cpe:/o: OS CPE from nmap osclass; null when absent. */
  osCpe: string | null;
  /**
   * True when this DOCKER_BRIDGE container publishes at least one host port
   * (i.e. the container's port is bound to 0.0.0.0 or a specific host interface).
   * False for internal-only containers. Always false for non-DOCKER_BRIDGE devices.
   */
  publishesHostPort: boolean;
  /**
   * Role classification for this device. Mirrors the backend
   * {@code DeviceRoleClassifier} first-match rule chain.
   * Defaults to {@code 'UNKNOWN'} for devices that have not been classified.
   */
  deviceRole: DeviceRole;
  /**
   * IP of the host from which this device was discovered. Value {@code "local"}
   * for all local-discovery paths (ARP/NMAP/Docker-CLI). A remote docker probe
   * writes the probed host's IP so the same container IP from two different hosts
   * becomes two distinct device rows. NOT NULL — defaults to {@code "local"}.
   */
  originHostIp: string;
  /**
   * Human-readable hostname of the origin host. Null for local discovery and when
   * the hostname is unknown at probe time.
   */
  originHostName: string | null;
  /**
   * Docker network name for container devices (e.g. {@code "bridge"},
   * {@code "pingpay_default"}). Null for non-docker devices and legacy rows.
   * Populated by the backend from the container's primary docker network (V30).
   */
  networkName: string | null;
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
  postureSeverity: string | null;
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

/**
 * Read-only summary returned by GET /api/cve/fleet listing. Excludes rawJson.
 *
 * <p><b>v3-F1 enrichment fields:</b> {@link #kev} is never null (defaults to false);
 * {@link #epssScore} and {@link #compositeScore} arrive from the backend as
 * Jackson-serialized BigDecimal strings — callers convert via {@code Number(x)}
 * before any arithmetic / comparison. {@code epssScore} is the raw probability
 * in [0, 1]; {@code compositeScore} is clamped to [0.00, 10.00]. Both are
 * {@code null} when no signal exists (no EPSS row / no CVSS metric).
 */
export interface CveSummaryDto {
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
  /** CISA KEV listing membership; never null (defaults to false on the wire). */
  kev: boolean;
  /** Raw EPSS probability in [0, 1] as a Jackson-serialized BigDecimal string; null if no row. */
  epssScore: string | null;
  /** Composite risk score in [0.00, 10.00] as a string; null if no CVSS metric. */
  compositeScore: string | null;
}

/**
 * Read-only DTO returned by GET /api/cve/{cveId}. Includes the upstream NVD rawJson.
 *
 * <p><b>v3-F1 enrichment fields:</b> appended AFTER {@link #rawJson}. Same semantics
 * as {@link CveSummaryDto} — composite uses {@code Criticality.MEDIUM} on this endpoint
 * since there's no device context (per analysis Decision 3).
 */
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
  /** CISA KEV listing membership; never null. */
  kev: boolean;
  /** Raw EPSS probability in [0, 1] as a string; null if no row. */
  epssScore: string | null;
  /** Composite risk score in [0.00, 10.00] as a string; null if no CVSS metric. */
  compositeScore: string | null;
}

/**
 * One device returned by GET /api/cve/{cveId}/devices (reverse fleet match).
 * Identifies the device and the first service that matched the target CVE.
 *
 * @remarks AC1 additive fields: {@link matchedCpe}, {@link matchedRangeStart},
 * {@link matchedRangeEnd} carry the NVD CPE row and version-range bounds that
 * caused the match, making "two devices share N CVEs" self-explanatory without
 * rewriting the matcher semantics.
 */
export interface CveAffectedDevice {
  deviceId: number;
  hostname: string | null;
  ipAddress: string;
  matchedPort: number;
  matchedService: string | null;
  matchedVersion: string | null;
  /**
   * CPE 2.3 URI of the NVD row that caused the match
   * (e.g. "cpe:2.3:a:postgresql:postgresql:*:...").
   * Null on legacy responses or when no evidence row exists.
   */
  matchedCpe: string | null;
  /**
   * Lower version bound of the matching CPE row as a human-readable string
   * (e.g. "14.0 (incl.)" or "14.0 (excl.)").
   * Null for literal CPE matches or when no lower bound exists.
   */
  matchedRangeStart: string | null;
  /**
   * Upper version bound of the matching CPE row as a human-readable string
   * (e.g. "17.0 (excl.)" or "16.14 (incl.)").
   * Null for literal CPE matches or when no upper bound exists.
   */
  matchedRangeEnd: string | null;
}

/** Sort key for {@code GET /api/cve/fleet}. {@code undefined} → backend default (cvssV31Score DESC). */
export type CveFleetSort = 'composite' | 'cvss' | 'kev' | 'epss';

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

export interface ScanDetail {
  id: number;
  cidr: string;
  scanType: ScanType;
  status: ScanStatus;
  requestedAt: string;
  completedAt: string | null;
  failureReason?: string | null;
  retryCount?: number;
  discoveredDeviceIds: number[];
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

/**
 * Response from GET /api/cve/coverage — corpus-coverage snapshot.
 *
 * @remarks AC3: When {@link thinCorpus} is true the UI should show a hint pointing
 * to the "Full NVD backfill" action. A corpus is considered thin when it has fewer
 * than 10 000 CVEs or the published year span is ≤ 1 year (skewed to recent only).
 */
export interface CveCoverageDto {
  /** Row count of the local NVD corpus; 0 on empty. */
  totalCves: number;
  /** Earliest calendar year of any published CVE; null when corpus empty. */
  earliestPublishedYear: number | null;
  /** Latest calendar year of any published CVE; null when corpus empty. */
  latestPublishedYear: number | null;
  /**
   * Number of KEV catalog entries whose cve_id exists in the corpus.
   * 0 is expected for a thin/new corpus — not a bug.
   */
  kevInCorpus: number;
  /**
   * True when the corpus looks thin (< 10 000 CVEs or year span ≤ 1).
   * The UI should show the full-backfill hint when this is true.
   */
  thinCorpus: boolean;
}

export interface InitialSyncRequest {
  since?: string;
  until?: string;
  /** When true, forces a full EPOCH→now backfill bypassing the incremental cursor. */
  fullBackfill?: boolean;
}

/** Response for the full-backfill trigger endpoint. Same shape as InitialSyncResponse. */
export type FullBackfillResponse = InitialSyncResponse;

export interface InitialSyncResponse {
  status: 'started' | 'already-running';
  startedAt: string;
}

export interface SyncStatusResponse {
  running: boolean;
  startedAt: string | null;
  lastCompletedAt: string | null;
  lastError: string | null;
}

export interface FeedScheduleDto {
  enabled: boolean;
  cron: string;
  lastRunAt: string | null;
  lastStatus: string | null;
  lastError: string | null;
  nextRunAt: string | null;
  consecutiveFailures: number;
}

export interface FeedScheduleUpdateRequest {
  enabled: boolean;
  cron: string;
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

/**
 * Passive and active discovery sources — mirrors the backend {@code DiscoverySource} enum.
 *
 * @remarks Full 10-value set: ARP | MDNS | PCAP | LLDP | CDP | OT_PROBE | NMAP_SCAN | DOCKER
 * | CONN_TABLE | GATEWAY. Previously this type omitted OT_PROBE and NMAP_SCAN; widened here
 * so {@link Device.discoverySource} is correctly typed for all backend values. DOCKER is the
 * local Docker-daemon inventory source ({@code POST /api/discovery/docker}). CONN_TABLE
 * reads the host's established-connection table (the main producer of PUBLIC-scope
 * devices); GATEWAY records the default-route egress router.
 */
export type DiscoverySource = 'ARP' | 'MDNS' | 'PCAP' | 'LLDP' | 'CDP' | 'OT_PROBE' | 'NMAP_SCAN' | 'DOCKER' | 'CONN_TABLE' | 'GATEWAY';

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

/** POST /api/discovery/docker — mirrors the backend {@code DockerDiscoveryResponse} record. */
export interface DockerDiscoveryResponse {
  /** Running containers discovered and upserted as devices. */
  containers: number;
  /** Synthetic docker-network gateway devices upserted (one per network). */
  gateways: number;
  /** Total devices upserted (containers + gateways) — the discovered/updated count. */
  updated: number;
  /** Ids of every upserted device (containers first, then gateways). */
  deviceIds: number[];
}

/** GET /api/discovery/interfaces — host-visible up, non-loopback NICs. */
export interface InterfaceInfo {
  name: string;
  displayName: string;
  mtu: number;
  /** First IPv4 address on this interface; null when none is assigned. Added in feat/active-network-cidr-autodetect. */
  ipAddress?: string | null;
  /** Network prefix length of {@code ipAddress}; 0 when unknown. */
  prefix?: number;
}

/**
 * Response from GET /api/discovery/active-cidr.
 * All string fields are null when no default route is detected (e.g. non-Linux / CI).
 * Empty shape: { iface: null, cidr: null, ipAddress: null, prefix: 0, note: null }.
 */
export interface ActiveCidr {
  iface: string | null;
  cidr: string | null;
  ipAddress: string | null;
  prefix: number;
  note?: string | null;
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

// ----- Per-scan report (Task 3.1) -----

/** Delta classification for a device row in a scan snapshot. Mirrors {@code ScanReportDto.SnapshotDeviceDto.delta}. */
export type ScanDelta = 'new' | 'changed' | 'unchanged';

/** Mirrors {@code ScanReportDto.ScanSummary} — scan metadata + aggregate counts. */
export interface ScanReportSummary {
  scanId: number;
  cidr: string;
  scanType: ScanType;
  status: ScanStatus;
  requestedAt: string;
  completedAt: string | null;
  durationMillis: number | null;
  failureReason?: string | null;
  retryCount?: number;
  deviceCount: number;
  serviceCount: number;
  cveCount: number;
}

/** Mirrors {@code ScanReportDto.ServiceRowDto} — per-service row nested inside a snapshot device. */
export interface ScanSnapshotService {
  id: number;
  port: number;
  protocol: string;
  name: string | null;
  version: string | null;
}

/** Mirrors {@code ScanReportDto.SnapshotDeviceDto} — per-device snapshot row with delta + services + CVE ids. */
export interface ScanSnapshotDevice {
  id: number;
  ipAddress: string;
  hostname: string | null;
  delta: ScanDelta;
  services: ScanSnapshotService[];
  cveIds: string[];
}

/** Top-level response from GET /api/scans/{id}/report. Mirrors {@code ScanReportDto}. */
export interface ScanReport {
  summary: ScanReportSummary;
  devices: ScanSnapshotDevice[];
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

// ----- Attack graph -----

/** Discriminator mirroring backend {@code io.castellum.graph.EdgeType}. */
export type EdgeType = 'SAME_SUBNET' | 'EXPLOITABLE_VULN' | 'WEAK_CRED_PATH';

/**
 * One hop on a shortest-path response. Each hop represents arrival at
 * {@link #deviceId} via {@link #edgeType}. The source of the edge is the
 * previous hop's {@code deviceId} (or the path's {@code from} when this is hop 0).
 *
 * <p>BigDecimal-typed fields are serialized as strings; callers convert via {@code Number(x)}.
 */
export interface HopDto {
  deviceId: number;
  ipAddress: string;
  edgeType: EdgeType;
  attackTechniqueId: string | null;
  attackTechniqueName: string | null;
  edgeRisk: string | null;
  cumulativeRisk: string | null;
  cveId: string | null;
}

/** Response shape for {@code GET /api/graph/shortest-path}. */
export interface ShortestPathResponse {
  from: number;
  to: number;
  hops: HopDto[];
  totalHops: number;
  cumulativeRisk: string | null;
  pathFound: boolean;
}

// ----- Integrations (TAXII / MISP) -----

/** Identifier for the threat-intel push integration backing a config row. */
export type IntegrationType = 'TAXII' | 'MISP';

/** Non-secret TAXII config keys persisted in {@code config_json}. */
export interface TaxiiConfigPayload {
  url: string;
  apiRoot?: string;
  collectionId?: string;
  username?: string;
}

/** Non-secret MISP config keys persisted in {@code config_json}. */
export interface MispConfigPayload {
  url: string;
}

/** Response shape for GET/PUT /api/integrations/{type}. */
export interface IntegrationConfigDto {
  id: number;
  integrationType: IntegrationType;
  config: Record<string, unknown>;
  credentialsSet: boolean;
  lastPushAt: string | null;
  lastPushStatus: string | null;
  createdAt: string;
  updatedAt: string;
}

/** Response shape for POST /api/integrations/{type}/push. */
export interface IntegrationPushResponse {
  status: 'ok' | 'error';
  bundleId: string | null;
  pushedAt: string;
  lastPushStatus: string;
}

/** Request body for POST /api/integrations/{type}/probe. */
export interface IntegrationProbeRequest {
  url: string;
  collectionId?: string;
}

/** Response shape for POST /api/integrations/{type}/probe. */
export interface IntegrationProbeResult {
  reachable: boolean;
  detail: string | null;
}
