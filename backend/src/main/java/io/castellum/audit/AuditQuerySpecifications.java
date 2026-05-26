package io.castellum.audit;

import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.criteria.Predicate;

public final class AuditQuerySpecifications {

    private AuditQuerySpecifications() {}

    public static Specification<AuditLog> build(AuditFilter f) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (f.since() != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("occurredAt"), f.since()));
            }
            if (f.until() != null) {
                predicates.add(cb.lessThan(root.get("occurredAt"), f.until()));
            }
            if (f.action() != null && !f.action().isBlank()) {
                predicates.add(cb.equal(root.get("action"), f.action()));
            }
            if (f.actor() != null && !f.actor().isBlank()) {
                predicates.add(cb.equal(root.get("actor"), f.actor()));
            }
            if (f.resourceType() != null && !f.resourceType().isBlank()) {
                predicates.add(cb.equal(root.get("resourceType"), f.resourceType()));
            }

            if (predicates.isEmpty()) {
                return cb.conjunction();
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}
