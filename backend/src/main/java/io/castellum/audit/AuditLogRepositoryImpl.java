package io.castellum.audit;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Order;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;

/**
 * Spring Data fragment impl for {@link AuditLogReadFragment}. Provides the read-only
 * {@code Specification} query methods that {@link AuditLogRepository} needs WITHOUT
 * inheriting from {@link org.springframework.data.jpa.repository.JpaSpecificationExecutor}
 * (which would expose {@code delete(Specification)} and break the append-only invariant).
 *
 * <p>Spring Data auto-detects this impl by the {@code Impl} suffix on the containing
 * repository's name.
 */
public class AuditLogRepositoryImpl implements AuditLogReadFragment {

    @PersistenceContext
    private EntityManager em;

    @Override
    public List<AuditLog> findAll(Specification<AuditLog> spec) {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<AuditLog> cq = cb.createQuery(AuditLog.class);
        Root<AuditLog> root = cq.from(AuditLog.class);
        applyPredicate(spec, root, cq, cb);
        return em.createQuery(cq).getResultList();
    }

    @Override
    public List<AuditLog> findAll(Specification<AuditLog> spec, Sort sort) {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<AuditLog> cq = cb.createQuery(AuditLog.class);
        Root<AuditLog> root = cq.from(AuditLog.class);
        applyPredicate(spec, root, cq, cb);
        if (sort != null && sort.isSorted()) {
            cq.orderBy(toOrders(sort, root, cb));
        }
        return em.createQuery(cq).getResultList();
    }

    @Override
    public Page<AuditLog> findAll(Specification<AuditLog> spec, Pageable pageable) {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<AuditLog> cq = cb.createQuery(AuditLog.class);
        Root<AuditLog> root = cq.from(AuditLog.class);
        applyPredicate(spec, root, cq, cb);
        if (pageable.getSort().isSorted()) {
            cq.orderBy(toOrders(pageable.getSort(), root, cb));
        }
        var typed = em.createQuery(cq);
        if (pageable.isPaged()) {
            typed.setFirstResult((int) pageable.getOffset());
            typed.setMaxResults(pageable.getPageSize());
        }
        List<AuditLog> rows = typed.getResultList();
        long total = count(spec);
        return new PageImpl<>(rows, pageable, total);
    }

    @Override
    public long count(Specification<AuditLog> spec) {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<Long> cq = cb.createQuery(Long.class);
        Root<AuditLog> root = cq.from(AuditLog.class);
        cq.select(cb.count(root));
        if (spec != null) {
            Predicate p = spec.toPredicate(root, cq, cb);
            if (p != null) cq.where(p);
        }
        return em.createQuery(cq).getSingleResult();
    }

    private static void applyPredicate(Specification<AuditLog> spec, Root<AuditLog> root,
                                       CriteriaQuery<AuditLog> cq, CriteriaBuilder cb) {
        if (spec == null) return;
        Predicate p = spec.toPredicate(root, cq, cb);
        if (p != null) cq.where(p);
    }

    private static List<Order> toOrders(Sort sort, Root<AuditLog> root, CriteriaBuilder cb) {
        List<Order> orders = new ArrayList<>();
        for (Sort.Order so : sort) {
            var path = root.get(so.getProperty());
            orders.add(so.isAscending() ? cb.asc(path) : cb.desc(path));
        }
        return orders;
    }
}
