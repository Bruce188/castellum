package io.castellum.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface DeviceRepository extends JpaRepository<Device, Long> {

    Optional<Device> findByIpAddress(String ipAddress);

    List<Device> findByIpAddressIn(Collection<String> ipAddresses);

    List<Device> findByMacAddressIn(Collection<String> macAddresses);

    @Query("SELECT d.id FROM Device d WHERE d.firstSeen BETWEEN :from AND :to")
    List<Long> findIdsByFirstSeenBetween(
        @Param("from") Instant from,
        @Param("to") Instant to);

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
}
