package io.castellum.discovery;

import io.castellum.audit.AuditService;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.DeviceRepository.StaleDeviceSample;
import io.castellum.risk.RiskCacheEvictor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Map;

/**
 * Separately-injected {@code @Service} that hard-deletes stale PUBLIC-scope devices not seen
 * within the configured TTL ({@code castellum.discovery.public-device-prune.ttl},
 * default {@code P14D}).
 *
 * <p><b>Atomic predicate delete:</b> the prune is ONE conditional bulk DELETE
 * ({@link DeviceRepository#deleteStaleByScopeAndSources}) that re-checks scope, staleness,
 * and attribution in the statement itself — never find-then-delete-by-id. Under
 * READ_COMMITTED, PostgreSQL re-evaluates the predicate after lock waits, so a device
 * concurrently refreshed by a sweep or re-scoped by an operator is skipped, and the
 * statement binds a fixed three parameters regardless of backlog size (no bind-parameter
 * cliff on the first run against a large pre-feature backlog).
 *
 * <p><b>Only passively-observed peers are eligible:</b> the {@link #PRUNABLE_SOURCES}
 * allowlist restricts deletion to passive observation sources whose {@code lastSeen} decays
 * naturally when the fleet stops talking to a peer (CONN_TABLE re-emits every live external
 * peer on each 6-hourly sweep, so a still-connected peer can never age past the TTL).
 * Deliberately excluded: {@code NMAP_SCAN} and {@code OT_PROBE} (their {@code lastSeen}
 * means "last scanned" — a monthly-scanned external asset must not vanish between scans),
 * {@code DOCKER} (container inventory, not an external peer), and NULL
 * {@code discoverySource} (manually POSTed devices; SQL {@code IN} never matches NULL).
 * Rows carrying scan attribution ({@code discoveredByScanId} / {@code lastSeenByScanId})
 * are likewise exempt — deliberately scanned, probed, or manually created assets are never
 * TTL-pruned.
 *
 * <p><b>Strict ISO-8601 TTL:</b> the constructor receives the raw property String and parses
 * it with {@link Duration#parse} — a bare number (e.g. {@code 31536000}) or a Spring
 * simple-style value (e.g. {@code 30d}) fails the application at boot — then rejects any
 * parsed duration below {@code PT1H}. Either way a misconfigured window can never
 * mass-delete the PUBLIC inventory at the 03:30 tick.
 *
 * <p><b>Operator escape hatches:</b>
 * <ul>
 *   <li>Disable the job outright: {@code castellum.discovery.public-device-prune.enabled=false}.</li>
 *   <li>Raise the retention window: set the {@code ttl} property (ISO-8601 duration).</li>
 *   <li>Keep a specific device forever: re-scope it off {@link DiscoveryScope#PUBLIC} — the
 *       IP-classified upsert paths never overwrite scope on update (see
 *       {@link DeviceUpsertService}), so an operator-set scope survives subsequent sweeps
 *       and the prune predicate never matches the row.</li>
 * </ul>
 *
 * <p><b>Auditing:</b> each run that deletes at least one row records exactly ONE summary
 * {@code DEVICE_PRUNE} event rather than a {@code DEVICE_DELETE} per row. Because the hard
 * delete destroys the {@code (ipAddress, originHostIp)} identity tuple, the payload carries
 * a pre-delete identity sample (id, ipAddress, originHostIp, lastSeen — capped at
 * {@link #AUDIT_SAMPLE_CAP}) plus the effective cutoff and TTL, so a forensic reader can
 * answer "which endpoints were removed, and was the window configured correctly?" from the
 * audit row alone. {@code count} (taken from the DELETE itself) is authoritative; the
 * sample is a best-effort pre-delete snapshot of the rows eligible at sweep start. The
 * sample and the DELETE are two separate READ_COMMITTED statements, so a device whose
 * {@code lastSeen} is refreshed between them is named in the sample yet skipped by the
 * DELETE — {@code sampleSize} can therefore fall below OR above {@code count}.
 *
 * <p><b>Cache eviction is after-commit:</b> evicting inside the transaction would let a
 * concurrent reader repopulate the risk caches from the pre-delete snapshot (the deletes are
 * not yet visible under READ_COMMITTED). When a transaction is active the eviction is
 * registered as an {@code afterCommit} synchronization; without one (plain unit tests) it
 * runs inline.
 *
 * <p><b>Residual race, accepted:</b> a prune commit landing mid-sweep can still fail one
 * passive sweep batch ({@code StaleStateException} on the sweep's flush of a row deleted
 * underneath it). The window is now a single short DELETE statement, the default crons
 * (03:30 daily vs every 6 h) do not collide, and a failed sweep self-heals at its next
 * firing — sweep-side retry is deliberately not added here.
 *
 * <p>The {@code @Transactional} annotation is on the public
 * {@link #pruneStalePublicDevices()} method only — the JPQL bulk delete requires an active
 * transaction. Child {@code service} rows are removed by the DB-level FK
 * {@code ON DELETE CASCADE} (V2__create_service.sql); JPQL bulk deletes bypass JPA cascade
 * metadata by design.
 */
@Service
public class DevicePruneService {

    /** Cap on the identity sample embedded in the audit payload — the count still reflects all rows. */
    private static final int AUDIT_SAMPLE_CAP = 50;

    /** Boot-time floor — a TTL below this is always a misconfiguration (see constructor). */
    private static final Duration MIN_TTL = Duration.ofHours(1);

    /**
     * Passive observation sources whose rows the prune may delete. Deliberately excludes
     * {@code NMAP_SCAN}, {@code OT_PROBE}, {@code DOCKER}, and (because SQL {@code IN}
     * never matches NULL) manually POSTed devices with no discovery source.
     */
    static final List<DiscoverySource> PRUNABLE_SOURCES = List.of(
        DiscoverySource.ARP,
        DiscoverySource.MDNS,
        DiscoverySource.PCAP,
        DiscoverySource.LLDP,
        DiscoverySource.CDP,
        DiscoverySource.CONN_TABLE,
        DiscoverySource.GATEWAY);

    private final DeviceRepository deviceRepository;
    private final AuditService auditService;
    private final RiskCacheEvictor riskCacheEvictor;
    private final Clock clock;
    private final Duration ttl;

    public DevicePruneService(DeviceRepository deviceRepository,
                              AuditService auditService,
                              RiskCacheEvictor riskCacheEvictor,
                              Clock clock,
                              @Value("${castellum.discovery.public-device-prune.ttl:P14D}") String ttlValue) {
        // The raw String is parsed here, strictly, instead of letting Spring convert: Spring's
        // lenient Duration conversion accepts a bare number as MILLISECONDS, so a value like
        // 31536000 (an operator intending seconds) would bind as ~8.76 hours and boot cleanly.
        Duration parsed;
        try {
            parsed = Duration.parse(ttlValue);
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException(
                "castellum.discovery.public-device-prune.ttl (env DISCOVERY_PUBLIC_DEVICE_TTL) is \""
                + ttlValue + "\", which is not an ISO-8601 duration. Bare numbers and simple-style"
                + " values (e.g. 30d) are rejected — use ISO-8601 such as P14D or PT12H.", e);
        }
        if (parsed.compareTo(MIN_TTL) < 0) {
            throw new IllegalArgumentException(
                "castellum.discovery.public-device-prune.ttl (env DISCOVERY_PUBLIC_DEVICE_TTL) is "
                + parsed + ", below the " + MIN_TTL + " minimum — use an ISO-8601 duration of at"
                + " least PT1H, such as P14D.");
        }
        this.deviceRepository = deviceRepository;
        this.auditService = auditService;
        this.riskCacheEvictor = riskCacheEvictor;
        this.clock = clock;
        this.ttl = parsed;
    }

    /**
     * Deletes every prune-eligible PUBLIC-scope device whose {@code lastSeen} predates
     * {@code clock.instant().minus(ttl)} (strict {@code <} — a row exactly AT the cutoff is
     * kept). An empty sweep is a true no-op: no audit row, no cache eviction — gated on the
     * DELETE's own row count, so a race that empties the stale set after the identity sample
     * was taken still no-ops. The audited {@code count} comes from the DELETE itself and is
     * authoritative; the identity sample is a best-effort pre-delete snapshot and may name a
     * row a concurrent {@code lastSeen} refresh caused the DELETE to skip.
     *
     * @return the number of devices pruned
     */
    @Transactional
    public int pruneStalePublicDevices() {
        Instant cutoff = clock.instant().minus(ttl);

        // Identity sample BEFORE the delete — the hard delete destroys the identity tuple.
        List<StaleDeviceSample> samples = deviceRepository.findStaleSamplesByScopeAndSources(
            DiscoveryScope.PUBLIC, cutoff, PRUNABLE_SOURCES,
            PageRequest.of(0, AUDIT_SAMPLE_CAP, Sort.by("lastSeen")));

        int deleted = deviceRepository.deleteStaleByScopeAndSources(
            DiscoveryScope.PUBLIC, cutoff, PRUNABLE_SOURCES);
        if (deleted == 0) {
            return 0;
        }

        List<Map<String, Object>> sample = samples.stream()
            .map(s -> Map.<String, Object>of(
                "id", s.getId(),
                "ipAddress", s.getIpAddress(),
                "originHostIp", s.getOriginHostIp(),
                "lastSeen", s.getLastSeen().toString()))
            .toList();
        auditService.recordEvent("scheduler", "DEVICE_PRUNE", "device", "-",
            Map.of("count", deleted,
                   "cutoff", cutoff.toString(),
                   "ttl", ttl.toString(),
                   "sampleSize", sample.size(),
                   "sample", sample));

        // Evict only once the deletes are visible to other readers — an in-transaction
        // eviction lets a concurrent request repopulate the caches from pre-delete rows.
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    riskCacheEvictor.onDevicesPruned();
                }
            });
        } else {
            riskCacheEvictor.onDevicesPruned();
        }
        return deleted;
    }
}
