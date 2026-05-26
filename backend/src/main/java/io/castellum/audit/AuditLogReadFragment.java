package io.castellum.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;

import java.util.List;

/**
 * Read-only Specification fragment for {@link AuditLogRepository}.
 *
 * <p>Defined as a sibling of {@link org.springframework.data.jpa.repository.JpaSpecificationExecutor}
 * that exposes ONLY the read methods. The full {@code JpaSpecificationExecutor} interface in
 * Spring Data JPA 3.0+ includes a {@code delete(Specification)} method, which would violate the
 * audit_log append-only invariant if mixed into the repository. By extending this fragment
 * instead, {@link AuditLogRepository} keeps its surface free of any {@code delete*} methods.
 *
 * <p>The implementation is provided by {@code AuditLogRepositoryImpl}, picked up automatically
 * by Spring Data's custom-fragment composition (suffix convention).
 */
public interface AuditLogReadFragment {

    List<AuditLog> findAll(Specification<AuditLog> spec);

    List<AuditLog> findAll(Specification<AuditLog> spec, Sort sort);

    Page<AuditLog> findAll(Specification<AuditLog> spec, Pageable pageable);

    long count(Specification<AuditLog> spec);
}
