package io.castellum.domain;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

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
     *
     * <p>{@code @Transactional} here gives this method its own self-committing transaction,
     * which is relied upon by {@link io.castellum.scan.ScanRecoveryService}: the CAS flip is
     * durable before the caller dispatches {@code executeAsync}, closing the lost-update window
     * that would exist if the dispatch raced an uncommitted outer transaction.
     *
     * <p>{@code clearAutomatically=true} evicts the persistence context after the UPDATE so
     * subsequent reads in the same session see the committed state. {@code flushAutomatically}
     * is left {@code false} (the default) — safe here because no dirty {@code Scan} writes
     * precede this CAS in the same transaction; the only mutation is this bulk UPDATE itself.
     * If a future caller ever mutates a {@code Scan} entity before calling this method in the
     * same TX, add {@code flushAutomatically=true} to ensure those dirty changes are flushed
     * before the UPDATE runs.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("UPDATE Scan s SET s.status = io.castellum.domain.ScanStatus.PENDING, " +
           "s.completedAt = null WHERE s.id = :id AND s.status = :expected")
    int claimForRecovery(@Param("id") Long id, @Param("expected") ScanStatus expected);
}
