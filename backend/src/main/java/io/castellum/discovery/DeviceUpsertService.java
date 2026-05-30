package io.castellum.discovery;

import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.risk.Criticality;
import io.castellum.discovery.RoleClassification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Separately-injected {@code @Service} that persists a single {@link Discovery}
 * observation into the {@link Device} inventory.
 *
 * <p>The {@code @Transactional} annotation is on the public {@link #upsert(Discovery)}
 * method only. No private helpers call {@code this.upsert(...)} — the proxy self-invocation
 * hazard is structurally avoided.
 *
 * <p>Upsert logic:
 * <ul>
 *   <li>Primary key: {@code ipAddress} (UNIQUE column).</li>
 *   <li>Existing row: update {@code lastSeen}; fill {@code macAddress} and {@code hostname}
 *       only if the existing values are {@code null}.</li>
 *   <li>Hostname priority policy: Docker bridge-gateway aliases (e.g. {@code host.docker.internal},
 *       {@code *.docker.internal}) are NEVER stored as a device hostname — they are artifacts of
 *       the Docker network stack, not real host identities. A real hostname always supersedes a
 *       stored bridge alias on a subsequent observation. Priority order:
 *       real hostname > null (no source) > bridge alias (rejected). The alias is never written.</li>
 *   <li>New row: create with {@link Criticality#MEDIUM} default and
 *       {@link io.castellum.discovery.DiscoveryScope} derived from {@code ipAddress} via
 *       {@link DiscoveryScopeClassifier#classify(String)}.</li>
 *   <li>Existing row: scope is NEVER touched, so an operator-set
 *       override (future endpoint) survives subsequent sweeps.</li>
 * </ul>
 */
@Service
public class DeviceUpsertService {

    /**
     * Docker bridge-gateway alias suffixes that must never be stored as a device hostname.
     * The gateway alias {@code host.docker.internal} (and any {@code *.docker.internal}
     * variant) is an artifact of the Docker network stack, not a real host identity.
     */
    private static boolean isBridgeAlias(String hostname) {
        if (hostname == null) return false;
        String lower = hostname.toLowerCase(java.util.Locale.ROOT);
        return lower.equals("host.docker.internal") || lower.endsWith(".docker.internal");
    }

    /**
     * Returns the effective hostname to store, applying the bridge-alias filter and the
     * override-alias policy:
     * <ul>
     *   <li>If the incoming hostname is a bridge alias → {@code null} (filtered out).</li>
     *   <li>Otherwise → the incoming hostname as-is (may be {@code null}).</li>
     * </ul>
     */
    private static String sanitizeHostname(String hostname) {
        return isBridgeAlias(hostname) ? null : hostname;
    }

    private final DeviceRepository repo;
    private final DiscoveryScopeClassifier scopeClassifier;
    private final DeviceRoleClassifier roleClassifier;

    public DeviceUpsertService(DeviceRepository repo, DiscoveryScopeClassifier scopeClassifier,
                               DeviceRoleClassifier roleClassifier) {
        this.repo = repo;
        this.scopeClassifier = scopeClassifier;
        this.roleClassifier = roleClassifier;
    }

    /**
     * Origin-aware, scope-explicit upsert. The full 3-argument form carrying an
     * {@link OriginContext} that determines which device row to find/create.
     *
     * <p>The {@code originContext} is written to {@code origin_host_ip} and
     * {@code origin_host_name} on BOTH the insert and update paths. Local discovery passes
     * {@link OriginContext#local()} ({@code "local"}/null) so the dedup semantics are
     * byte-identical to the pre-V27 behaviour. A remote docker probe passes
     * {@link OriginContext#of(String, String)} with the probed host's IP so the same internal
     * container IP (e.g. {@code 172.17.0.2}) from two docker hosts becomes two separate rows
     * under the composite {@code UNIQUE(ip_address, origin_host_ip)} constraint.
     *
     * <p>All other field semantics (mac/hostname fill-when-null, scope authoritative
     * last-writer-wins, osName fill-when-null, publishesHostPort last-writer-wins,
     * role non-downgrade) are unchanged from the 2-arg variant.
     *
     * @param d      the observation
     * @param scope  authoritative scope, overriding the IP-range classifier
     * @param origin origin context for the discovering host
     * @return the persisted device
     */
    @Transactional
    public Device upsertWithScope(Discovery d, DiscoveryScope scope, OriginContext origin) {
        Optional<Device> existing = repo.findByIpAddressAndOriginHostIp(d.ipAddress(), origin.originHostIp());
        if (existing.isPresent()) {
            Device e = existing.get();
            e.setLastSeen(d.observedAt());
            if (e.getMacAddress() == null && d.macAddress() != null) {
                e.setMacAddress(d.macAddress());
            }
            // hostname: overwrite-always for the scope-explicit path. A container's name is a
            // stable, authoritative identifier (re-create keeps the same name); refreshing it
            // keeps the topology label current if a prior null/stale source seeded the row.
            // Bridge alias filtered via sanitizeHostname — defense-in-depth: a container
            // pathologically named host.docker.internal must not bypass the AC1 policy.
            String incomingHostname = sanitizeHostname(d.hostname());
            if (incomingHostname != null) {
                e.setHostname(incomingHostname);
            }
            if (d.iface() != null) {
                e.setLastSeenIface(d.iface());
            }
            e.setDiscoverySource(d.source());
            // Authoritative scope — written on update too (see method Javadoc).
            e.setDiscoveryScope(scope);
            // publishesHostPort: last-writer-wins — a container that starts or stops publishing
            // a host port between sweeps must reflect the latest state in place.
            e.setPublishesHostPort(d.publishesHostPort());
            // AC1: Docker containers run on Linux — fill default OS when scope is DOCKER_BRIDGE
            // and no OS has been determined yet. Fill-when-null mirrors mac/hostname semantics:
            // a prior OS_FINGERPRINT nmap scan may have set a more-specific name (e.g. "Linux 5.15")
            // that must not be overwritten back to the generic default.
            if (scope == DiscoveryScope.DOCKER_BRIDGE
                    && (e.getOsName() == null || e.getOsName().isBlank())) {
                e.setOsName("Linux");
            }
            // Origin: update both columns so a row can move origin if needed (last-writer-wins).
            e.setOriginHostIp(origin.originHostIp());
            e.setOriginHostName(origin.originHostName());
            // Non-downgrade role write (UPDATE branch): classify after all other fields are set.
            // Never overwrite a known role with UNKNOWN — a signal-less re-sweep must not flap.
            RoleClassification rcU = roleClassifier.classifyWithConfidence(e);
            if (rcU.role() != DeviceRole.UNKNOWN || e.getDeviceRole() == DeviceRole.UNKNOWN) {
                e.setDeviceRole(rcU.role());
                e.setRoleConfidence(rcU.confidence());
            }
            return repo.save(e);
        } else {
            // sanitizeHostname on insert — mirrors the update branch above.
            String insertHostname = sanitizeHostname(d.hostname());
            Instant now = d.observedAt();
            Device fresh = new Device(
                null,
                d.ipAddress(),
                insertHostname,
                d.macAddress(),
                now,
                now,
                Criticality.MEDIUM
            );
            fresh.setDiscoveryScope(scope);
            fresh.setLastSeenIface(d.iface());
            fresh.setDiscoverySource(d.source());
            // publishesHostPort: persisted on insert from the Discovery (last-writer-wins on update).
            fresh.setPublishesHostPort(d.publishesHostPort());
            // AC1: Docker containers run on Linux — set default OS when scope is DOCKER_BRIDGE.
            if (scope == DiscoveryScope.DOCKER_BRIDGE) {
                fresh.setOsName("Linux");
            }
            // Origin: set on insert.
            fresh.setOriginHostIp(origin.originHostIp());
            fresh.setOriginHostName(origin.originHostName());
            // Non-downgrade role write (INSERT branch): fresh device starts at entity default UNKNOWN,
            // so the guard always permits the first classification.
            RoleClassification rcI = roleClassifier.classifyWithConfidence(fresh);
            if (rcI.role() != DeviceRole.UNKNOWN || fresh.getDeviceRole() == DeviceRole.UNKNOWN) {
                fresh.setDeviceRole(rcI.role());
                fresh.setRoleConfidence(rcI.confidence());
            }
            return repo.save(fresh);
        }
    }

    /**
     * Scope-explicit upsert for sources whose {@link DiscoveryScope} is determined by
     * runtime metadata rather than the IP-range heuristic in {@link DiscoveryScopeClassifier}.
     *
     * <p>The Docker discovery path uses this: all containers get
     * {@link DiscoveryScope#DOCKER_BRIDGE} — Docker source is authoritative for scope,
     * regardless of network subnet (custom docker networks can use any RFC1918 range).
     * Synthetic gateways still use {@link DiscoveryScope#DOCKER_BRIDGE}.
     *
     * <p>Delegates to {@link #upsertWithScope(Discovery, DiscoveryScope, OriginContext)} with
     * {@link OriginContext#local()} — all local-discovery callers use this overload and get
     * byte-identical dedup semantics (origin='local').
     *
     * @param d     the observation (its {@link Discovery#source()} is persisted as-is)
     * @param scope the authoritative scope to write, overriding the IP-range classifier
     * @return the persisted device
     */
    @Transactional
    public Device upsertWithScope(Discovery d, DiscoveryScope scope) {
        return upsertWithScope(d, scope, OriginContext.local());
    }

    /**
     * Scan-only upsert overload. Performs the same upsert as {@link #upsert(Discovery)} and
     * additionally writes scan attribution columns when {@code scanId} is non-null:
     * <ul>
     *   <li>INSERT: sets {@code discoveredByScanId = scanId} AND {@code lastSeenByScanId = scanId}.</li>
     *   <li>UPDATE: sets {@code lastSeenByScanId = scanId}; sets {@code discoveredByScanId = scanId}
     *       ONLY if it is currently null (insert-once / first-discovery sticky — never overwrite).</li>
     * </ul>
     * When {@code scanId} is {@code null}, behaves identically to {@link #upsert(Discovery)} and
     * writes NO attribution — non-scan callers (docker/passive/ARP) are unaffected.
     */
    @Transactional
    public Device upsert(Discovery d, Long scanId) {
        String incomingHostname = sanitizeHostname(d.hostname());
        // Origin-aware lookup: scan/ARP/NMAP/passive callers are always 'local'.
        Optional<Device> existing = repo.findByIpAddressAndOriginHostIp(d.ipAddress(), "local");
        if (existing.isPresent()) {
            Device e = existing.get();
            e.setLastSeen(d.observedAt());
            if (e.getMacAddress() == null && d.macAddress() != null) {
                e.setMacAddress(d.macAddress());
            }
            // Hostname priority policy:
            //   1. Never set: incoming is a bridge alias (filtered to null by sanitizeHostname).
            //   2. Fill: existing is null and incoming is a real hostname.
            //   3. Override alias: existing is a bridge alias and incoming is a real hostname
            //      — a stale alias that somehow persisted must be superseded by any real name.
            //   4. Preserve: existing is already a real hostname — never overwrite.
            if (incomingHostname != null) {
                if (e.getHostname() == null || isBridgeAlias(e.getHostname())) {
                    e.setHostname(incomingHostname);
                }
            }
            // iface uses overwrite-only-when-non-null — the inverse of mac/hostname's
            // fill-only-when-prior-null. ARP rescan SHOULD replace stale iface (cable swap);
            // NMAP/OT rescan carries no iface and MUST NOT clobber the prior value.
            if (d.iface() != null) {
                e.setLastSeenIface(d.iface());
            }
            // discoverySource: overwrite always (last-writer-wins, mirrors lastSeen).
            e.setDiscoverySource(d.source());
            // Origin: local rows always have origin='local'/null; ensure column is set on update.
            e.setOriginHostIp("local");
            // Scan attribution (UPDATE path):
            //   lastSeenByScanId: last-writer-wins — always set when scanId is present.
            //   discoveredByScanId: insert-once — only fill when currently null (first-discovery sticky).
            if (scanId != null) {
                e.setLastSeenByScanId(scanId);
                if (e.getDiscoveredByScanId() == null) {
                    e.setDiscoveredByScanId(scanId);
                }
            }
            // Non-downgrade role write (UPDATE branch).
            RoleClassification rcUpsertU = roleClassifier.classifyWithConfidence(e);
            if (rcUpsertU.role() != DeviceRole.UNKNOWN || e.getDeviceRole() == DeviceRole.UNKNOWN) {
                e.setDeviceRole(rcUpsertU.role());
                e.setRoleConfidence(rcUpsertU.confidence());
            }
            return repo.save(e);
        } else {
            Instant now = d.observedAt();
            Device fresh = new Device(
                null,
                d.ipAddress(),
                incomingHostname,   // bridge alias filtered to null
                d.macAddress(),
                now,
                now,
                Criticality.MEDIUM
            );
            fresh.setDiscoveryScope(scopeClassifier.classify(d.ipAddress()));
            fresh.setLastSeenIface(d.iface());
            // discoverySource: last-writer-wins (mirrors lastSeen; see update branch above).
            fresh.setDiscoverySource(d.source());
            // Origin: local path — entity default "local" is already set, confirm explicitly.
            fresh.setOriginHostIp("local");
            // Scan attribution (INSERT path): set both columns when scanId is present.
            if (scanId != null) {
                fresh.setDiscoveredByScanId(scanId);
                fresh.setLastSeenByScanId(scanId);
            }
            // Non-downgrade role write (INSERT branch).
            RoleClassification rcUpsertI = roleClassifier.classifyWithConfidence(fresh);
            if (rcUpsertI.role() != DeviceRole.UNKNOWN || fresh.getDeviceRole() == DeviceRole.UNKNOWN) {
                fresh.setDeviceRole(rcUpsertI.role());
                fresh.setRoleConfidence(rcUpsertI.confidence());
            }
            return repo.save(fresh);
        }
    }

    /**
     * Non-scan upsert. Delegates to {@link #upsert(Discovery, Long)} with {@code null} scanId —
     * writes NO scan attribution. Docker/passive/ARP callers use this entry point.
     */
    @Transactional
    public Device upsert(Discovery d) {
        return upsert(d, null);
    }

    /**
     * Batch counterpart to {@link #upsert(Discovery)}. Issues exactly one
     * {@link DeviceRepository#findByIpAddressIn} (read) plus one or two {@code saveAll}
     * calls (insert + update lists, kept separate so {@code hibernate.order_inserts}
     * can batch each homogeneous list cleanly).
     *
     * <p>Returns devices in the same order as the input list, so callers can correlate
     * {@code deviceIds} with their original {@link Discovery} sequence.
     *
     * <p><b>Atomic-sweep contract (AC5):</b> this method is intentionally {@code @Transactional}
     * all-or-nothing. A passive sweep is a single audit unit; if any upsert fails the whole
     * batch rolls back and the sweep is recorded FAILED. Per-row catch-and-continue is
     * explicitly <em>not</em> used. This design is safe because:
     * <ul>
     *   <li>The batch is deduped upstream by {@link PassiveDiscoveryService} (MAC-primary, then
     *       IP-fallback) so an intra-batch IP collision cannot occur.</li>
     *   <li>AC1 (every observed IP added to {@code ipSet} unconditionally) closes the
     *       DB-vs-batch keying gap: a MAC-bearing re-observation of a known-IP/null-MAC row
     *       now hits the UPDATE branch, preventing the {@code device_ip_unique} violation that
     *       previously caused sweeps to be recorded FAILED.</li>
     * </ul>
     *
     * @param discoveries unique-by-IP discoveries (callers should dedupe upstream)
     * @return persisted devices in input order
     */
    @Transactional
    public List<Device> upsertAll(List<Discovery> discoveries) {
        if (discoveries == null || discoveries.isEmpty()) {
            return List.of();
        }

        // Partition into MAC-bearing vs IP-only. MAC is the strongest equality key —
        // matching devices by MAC first prevents IP-renumber events from spawning duplicate rows.
        // Every observed IP is added to ipSet unconditionally (AC1): a MAC-bearing discovery
        // of a known-IP/null-MAC row must also hit the existingByIp fallback lookup so it
        // takes the UPDATE branch and backfills the null MAC in place.
        Set<String> macSet = new HashSet<>();
        Set<String> ipSet = new HashSet<>();
        for (Discovery d : discoveries) {
            if (d.macAddress() != null && !d.macAddress().isBlank()) {
                macSet.add(d.macAddress());
            }
            ipSet.add(d.ipAddress());   // ALWAYS — every observed IP is an existence candidate
        }

        Map<String, Device> existingByMac = new HashMap<>();
        if (!macSet.isEmpty()) {
            for (Device d : repo.findByMacAddressIn(macSet)) {
                if (d.getMacAddress() != null) {
                    existingByMac.put(d.getMacAddress(), d);
                }
            }
        }

        // Key by (ip, 'local') — all upsertAll callers are local-discovery paths.
        // fetch candidates by IP, then re-key by ip to match below (all are origin='local').
        Map<String, Device> existingByIp = new HashMap<>();
        if (!ipSet.isEmpty()) {
            for (Device d : repo.findByIpAddressIn(ipSet)) {
                // Only consider local rows — remote-origin rows with the same IP must not match
                // here (they are a different device row under composite uniqueness).
                if ("local".equals(d.getOriginHostIp())) {
                    existingByIp.put(d.getIpAddress(), d);
                }
            }
        }

        List<Device> updates = new ArrayList<>();
        List<Device> inserts = new ArrayList<>();
        // Track which list each input maps to so we can return in input order
        // after both saveAll calls have run (and inserts have IDs assigned).
        record Slot(boolean isUpdate, int idx) {}
        List<Slot> slots = new ArrayList<>(discoveries.size());

        for (Discovery d : discoveries) {
            String incomingHostname = sanitizeHostname(d.hostname());
            Device existing = null;
            if (d.macAddress() != null && !d.macAddress().isBlank()) {
                existing = existingByMac.get(d.macAddress());
            }
            if (existing == null) {
                existing = existingByIp.get(d.ipAddress());
            }
            if (existing != null) {
                existing.setLastSeen(d.observedAt());
                // MAC-keyed match: refresh IP if it changed (renumber event)
                if (d.ipAddress() != null && !d.ipAddress().equals(existing.getIpAddress())) {
                    existing.setIpAddress(d.ipAddress());
                }
                if (existing.getMacAddress() == null && d.macAddress() != null) {
                    existing.setMacAddress(d.macAddress());
                }
                // Hostname priority: same as upsert(Discovery) — never store bridge alias;
                // real hostname fills null or supersedes a stored alias.
                if (incomingHostname != null) {
                    if (existing.getHostname() == null || isBridgeAlias(existing.getHostname())) {
                        existing.setHostname(incomingHostname);
                    }
                }
                // iface overwrite-only-when-non-null (inverse of mac/hostname). See
                // upsert(Discovery) for rationale.
                if (d.iface() != null) {
                    existing.setLastSeenIface(d.iface());
                }
                // discoverySource: last-writer-wins (mirrors lastSeen; see upsert single-path).
                existing.setDiscoverySource(d.source());
                // Origin: local batch — confirm local origin on update.
                existing.setOriginHostIp("local");
                // Non-downgrade role write (UPDATE branch).
                RoleClassification rcAllU = roleClassifier.classifyWithConfidence(existing);
                if (rcAllU.role() != DeviceRole.UNKNOWN || existing.getDeviceRole() == DeviceRole.UNKNOWN) {
                    existing.setDeviceRole(rcAllU.role());
                    existing.setRoleConfidence(rcAllU.confidence());
                }
                slots.add(new Slot(true, updates.size()));
                updates.add(existing);
            } else {
                Instant now = d.observedAt();
                Device fresh = new Device(null, d.ipAddress(), incomingHostname, d.macAddress(),
                    now, now, Criticality.MEDIUM);
                fresh.setDiscoveryScope(scopeClassifier.classify(d.ipAddress()));
                fresh.setLastSeenIface(d.iface());
                // discoverySource: last-writer-wins (mirrors lastSeen; see upsert single-path).
                fresh.setDiscoverySource(d.source());
                // Origin: local batch — entity default "local" is already set, confirm explicitly.
                fresh.setOriginHostIp("local");
                // Non-downgrade role write (INSERT branch).
                RoleClassification rcAllI = roleClassifier.classifyWithConfidence(fresh);
                if (rcAllI.role() != DeviceRole.UNKNOWN || fresh.getDeviceRole() == DeviceRole.UNKNOWN) {
                    fresh.setDeviceRole(rcAllI.role());
                    fresh.setRoleConfidence(rcAllI.confidence());
                }
                slots.add(new Slot(false, inserts.size()));
                inserts.add(fresh);
            }
        }

        List<Device> savedUpdates = updates.isEmpty() ? List.of() : repo.saveAll(updates);
        List<Device> savedInserts = inserts.isEmpty() ? List.of() : repo.saveAll(inserts);

        List<Device> result = new ArrayList<>(discoveries.size());
        for (Slot s : slots) {
            result.add(s.isUpdate() ? savedUpdates.get(s.idx()) : savedInserts.get(s.idx()));
        }
        return result;
    }
}
