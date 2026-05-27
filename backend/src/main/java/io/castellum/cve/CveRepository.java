package io.castellum.cve;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;

public interface CveRepository extends JpaRepository<Cve, Long> {

    Optional<Cve> findByCveId(String cveId);

    @Query("SELECT MAX(c.lastModified) FROM Cve c")
    Optional<Instant> findMaxLastModified();

    Page<Cve> findByCvssV31ScoreIsNotNull(Pageable pageable);

    Page<Cve> findByCvssV31ScoreGreaterThanEqual(BigDecimal minScore, Pageable pageable);

    Page<Cve> findByIdInAndCvssV31ScoreIsNotNull(Set<Long> ids, Pageable pageable);

    Page<Cve> findByIdInAndCvssV31ScoreGreaterThanEqual(Set<Long> ids, BigDecimal minScore, Pageable pageable);

    // v3-F1 — kevOnly fleet branch. Spring Data JPA generates the IN-clause and
    // CvssV31Score IS NOT NULL predicate; no @Query annotation needed.
    Page<Cve> findByCveIdInAndCvssV31ScoreIsNotNull(Set<String> cveIds, Pageable pageable);

    // kevOnly fleet branch — intersect the fleet-matched FK set (PK id IN) with the
    // KEV catalog (cveId IN), keeping paging at the DB level. Same derivation
    // convention as findByIdInAndCvssV31ScoreIsNotNull above.
    Page<Cve> findByIdInAndCveIdInAndCvssV31ScoreIsNotNull(Set<Long> ids, Collection<String> cveIds, Pageable pageable);
}
