package io.castellum.audit;

import org.springframework.data.repository.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Append-only repository for audit_log. Only non-mutating reads and the single
 * {@link #save} write method are exposed. By extending the base {@link Repository}
 * (not {@link org.springframework.data.jpa.repository.JpaRepository}), the
 * {@code delete*} and bulk-{@code save} methods are not part of the public API,
 * so callers cannot accidentally UPDATE or DELETE audit rows.
 *
 * <p>Spring Data recognises {@code save} and {@code findById} / {@code findAll}
 * as built-in operations even on the minimal {@link Repository} base, so no
 * custom {@code @Query} annotations are needed here.
 *
 * <p>{@link AuditLogReadFragment} contributes the read-only {@code Specification}
 * query methods (paged + sorted + count) — implemented by {@link AuditLogRepositoryImpl}.
 * Crucially, this fragment exposes NO {@code delete} methods, so the reflection guard
 * {@code AuditLogRepositoryTest.auditLogRepository_declaresNoDeleteMethods} stays green.
 */
public interface AuditLogRepository extends Repository<AuditLog, Long>, AuditLogReadFragment {

    /**
     * Persist a new audit event. Always creates a new row (insert-only) because
     * {@link AuditLog} entities are built without an id, so Hibernate always issues
     * an INSERT rather than an UPDATE.
     */
    AuditLog save(AuditLog auditLog);

    Optional<AuditLog> findById(Long id);

    List<AuditLog> findAll();

    List<AuditLog> findByActor(String actor);
}
