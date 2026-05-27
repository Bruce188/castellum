package io.castellum.domain;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;

public interface ScanRepository extends JpaRepository<Scan, Long> {

    List<Scan> findByStatus(ScanStatus status);

    /**
     * Returns the recovery set: all PENDING scans plus any RUNNING scans whose
     * {@code requestedAt} predates this process start (stale-RUNNING orphans from a
     * previous JVM that died mid-scan).
     */
    @Query("SELECT s FROM Scan s WHERE s.status = io.castellum.domain.ScanStatus.PENDING " +
           "OR (s.status = io.castellum.domain.ScanStatus.RUNNING AND s.requestedAt < :processStart)")
    List<Scan> findRecoverable(@Param("processStart") Instant processStart);

    /**
     * Guarded compare-and-set claim for recovery. Updates the row to PENDING (clearing
     * {@code completedAt}) only when the current status still matches {@code expected}.
     * Returns 1 if the row was updated, 0 if the status had already changed (concurrent actor).
     */
    @Modifying(clearAutomatically = true)
    @Query("UPDATE Scan s SET s.status = io.castellum.domain.ScanStatus.PENDING, " +
           "s.completedAt = null WHERE s.id = :id AND s.status = :expected")
    int claimForRecovery(@Param("id") Long id, @Param("expected") ScanStatus expected);
}
