package io.castellum.discovery;

import io.castellum.audit.AuditService;
import io.castellum.domain.DeviceRepository;
import io.castellum.risk.RiskCacheEvictor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Separately-injected {@code @Service} that hard-deletes PUBLIC-scope devices not seen
 * within the configured TTL ({@code castellum.discovery.public-device-prune.ttl},
 * default {@code P14D}).
 *
 * <p><b>Why this is safe:</b> the CONN_TABLE discovery source re-emits every live external
 * peer on each passive sweep (every 6 hours by default), refreshing {@code lastSeen} on the
 * matching PUBLIC row. A still-connected peer therefore can never age past a 14-day TTL —
 * anything PUBLIC whose {@code lastSeen} is older than the cutoff is an external endpoint
 * the fleet genuinely stopped talking to, and keeping it only inflates the inventory and
 * the risk aggregates with dead rows.
 *
 * <p><b>Operator escape hatches:</b>
 * <ul>
 *   <li>Disable the job outright: {@code castellum.discovery.public-device-prune.enabled=false}.</li>
 *   <li>Raise the retention window: set the {@code ttl} property (ISO-8601 duration).</li>
 *   <li>Keep a specific device forever: re-scope it off {@link DiscoveryScope#PUBLIC} — the
 *       IP-classified upsert paths never overwrite scope on update (see
 *       {@link DeviceUpsertService}), so an operator-set scope survives subsequent sweeps
 *       and the prune query never sees the row.</li>
 * </ul>
 *
 * <p><b>Auditing:</b> each non-empty run records exactly ONE summary {@code DEVICE_PRUNE}
 * event (count + id sample capped at 50) rather than a {@code DEVICE_DELETE} per row —
 * at conn-table scale a single sweep can retire hundreds of peers, and per-row events
 * would write hundreds of audit rows per run for no additional forensic value.
 *
 * <p>The {@code @Transactional} annotation is on the public
 * {@link #pruneStalePublicDevices()} method only — the JPQL bulk delete issued by
 * {@code deleteAllByIdInBatch} requires an active transaction. Child {@code service} rows
 * are removed by the DB-level FK {@code ON DELETE CASCADE} (V2__create_service.sql);
 * JPQL bulk deletes bypass JPA cascade metadata by design.
 */
@Service
public class DevicePruneService {

    /** Cap on the id list embedded in the audit payload — the count still reflects all rows. */
    private static final int AUDIT_ID_CAP = 50;

    private final DeviceRepository deviceRepository;
    private final AuditService auditService;
    private final RiskCacheEvictor riskCacheEvictor;
    private final Clock clock;
    private final Duration ttl;

    public DevicePruneService(DeviceRepository deviceRepository,
                              AuditService auditService,
                              RiskCacheEvictor riskCacheEvictor,
                              Clock clock,
                              @Value("${castellum.discovery.public-device-prune.ttl:P14D}") Duration ttl) {
        this.deviceRepository = deviceRepository;
        this.auditService = auditService;
        this.riskCacheEvictor = riskCacheEvictor;
        this.clock = clock;
        this.ttl = ttl;
    }

    /**
     * Deletes every PUBLIC-scope device whose {@code lastSeen} predates
     * {@code clock.instant().minus(ttl)}. An empty sweep is a true no-op: no delete, no
     * audit row, no cache eviction.
     *
     * @return the number of devices pruned
     */
    @Transactional
    public int pruneStalePublicDevices() {
        Instant cutoff = clock.instant().minus(ttl);
        List<Long> staleIds =
            deviceRepository.findIdsByDiscoveryScopeAndLastSeenBefore(DiscoveryScope.PUBLIC, cutoff);
        if (staleIds.isEmpty()) {
            return 0;
        }

        // Single JPQL bulk delete — never one-by-one. DB FK cascade cleans up service rows.
        deviceRepository.deleteAllByIdInBatch(staleIds);

        List<Long> sampleIds = staleIds.size() > AUDIT_ID_CAP
            ? staleIds.subList(0, AUDIT_ID_CAP)
            : staleIds;
        auditService.recordEvent("scheduler", "DEVICE_PRUNE", "device", "-",
            Map.of("count", staleIds.size(), "deviceIds", sampleIds));

        riskCacheEvictor.onDevicesPruned();
        return staleIds.size();
    }
}
