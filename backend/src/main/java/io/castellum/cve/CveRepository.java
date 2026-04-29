package io.castellum.cve;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.Optional;

public interface CveRepository extends JpaRepository<Cve, Long> {

    Optional<Cve> findByCveId(String cveId);

    @Query("SELECT MAX(c.lastModified) FROM Cve c")
    Optional<Instant> findMaxLastModified();
}
