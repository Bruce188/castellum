package io.castellum.domain;

import io.castellum.discovery.DiscoveryScope;
import io.castellum.discovery.DiscoverySource;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface DeviceRepository extends JpaRepository<Device, Long> {

    Optional<Device> findByIpAddress(String ipAddress);

    /**
     * Origin-aware single-device lookup used by the origin-aware upsert paths (Task 1.2).
     * Replaces {@link #findByIpAddress(String)} in {@code upsertWithScope} and
     * {@code upsert(Discovery, Long)} so two devices sharing the same internal IP but
     * discovered from different origin hosts are correctly identified.
     */
    Optional<Device> findByIpAddressAndOriginHostIp(String ipAddress, String originHostIp);

    List<Device> findByIpAddressIn(Collection<String> ipAddresses);

    List<Device> findByMacAddressIn(Collection<String> macAddresses);

    /**
     * All known device IP addresses. Used by the alive-host resolver to scope SERVICE_DETECT
     * to hosts within a CIDR. IPv4-in-CIDR membership is not expressible as a portable JPQL
     * predicate, so the caller filters in-process; the device inventory is bounded
     * (see {@code castellum.graph.max-devices}, default 1024) so a full fetch is cheap.
     */
    @Query("SELECT d.ipAddress FROM Device d")
    List<String> findAllIpAddresses();

    // ── Task 1.2 stubs — attribution queries (implementer wires to real columns) ─────────────

    /** Returns IDs of devices whose first observation was attributed to the given scan (insert-once). */
    @Query("SELECT d.id FROM Device d WHERE d.discoveredByScanId = :scanId")
    List<Long> findIdsByDiscoveredByScanId(@Param("scanId") Long scanId);

    /** Returns IDs of devices most recently observed by the given scan (last-writer-wins). */
    @Query("SELECT d.id FROM Device d WHERE d.lastSeenByScanId = :scanId")
    List<Long> findIdsByLastSeenByScanId(@Param("scanId") Long scanId);

    /** Returns full Device rows most recently observed by the given scan. */
    List<Device> findByLastSeenByScanId(Long scanId);

    /**
     * Identity projection of prune-eligible devices, used to build the audit payload for
     * the TTL prune BEFORE the hard delete destroys the {@code (ipAddress, originHostIp)}
     * identity tuple. Carries exactly the fields a forensic reader needs to answer
     * "which external endpoints were removed, and when were they last seen?".
     */
    interface StaleDeviceSample {
        Long getId();
        String getIpAddress();
        String getOriginHostIp();
        Instant getLastSeen();
    }

    /**
     * Atomic predicate-based bulk delete for the PUBLIC-device TTL prune.
     *
     * <p>The DELETE re-checks scope, staleness, and attribution in ONE statement — there is
     * no find-then-delete window. Under READ_COMMITTED, PostgreSQL re-evaluates the predicate
     * after a lock wait, so a row concurrently refreshed (lastSeen bumped by a sweep) or
     * re-scoped off PUBLIC by an operator is simply skipped, never deleted. The statement
     * also binds only three parameter slots regardless of backlog size, so the first run
     * against a large pre-feature backlog cannot hit the pgjdbc 65535-bind-parameter cliff
     * that an {@code id IN (...)} delete would.
     *
     * <p>Rows with scan attribution ({@code discoveredByScanId} / {@code lastSeenByScanId})
     * are excluded: their {@code lastSeen} means "last scanned", not "fleet stopped talking
     * to it". The {@code discoverySource IN :sources} clause restricts deletion to the
     * caller's passive-source allowlist and — because SQL {@code IN} never matches NULL —
     * also exempts manually POSTed devices (NULL {@code discoverySource}).
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("DELETE FROM Device d WHERE d.discoveryScope = :scope AND d.lastSeen < :cutoff"
        + " AND d.discoveredByScanId IS NULL AND d.lastSeenByScanId IS NULL"
        + " AND d.discoverySource IN :sources")
    int deleteStaleByScopeAndSources(@Param("scope") DiscoveryScope scope,
                                     @Param("cutoff") Instant cutoff,
                                     @Param("sources") Collection<DiscoverySource> sources);

    /**
     * Capped pre-delete identity sample over the SAME predicate as
     * {@link #deleteStaleByScopeAndSources}. Feeds the audit payload only — the delete is
     * gated on its own row count, never on this sample, so a race that empties the stale
     * set between the two statements stays a no-op.
     */
    @Query("SELECT d.id AS id, d.ipAddress AS ipAddress, d.originHostIp AS originHostIp,"
        + " d.lastSeen AS lastSeen"
        + " FROM Device d WHERE d.discoveryScope = :scope AND d.lastSeen < :cutoff"
        + " AND d.discoveredByScanId IS NULL AND d.lastSeenByScanId IS NULL"
        + " AND d.discoverySource IN :sources")
    List<StaleDeviceSample> findStaleSamplesByScopeAndSources(@Param("scope") DiscoveryScope scope,
                                                              @Param("cutoff") Instant cutoff,
                                                              @Param("sources") Collection<DiscoverySource> sources,
                                                              Pageable pageable);
}
