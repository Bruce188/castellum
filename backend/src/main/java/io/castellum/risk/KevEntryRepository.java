package io.castellum.risk;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.Optional;

public interface KevEntryRepository extends JpaRepository<KevEntry, Long> {
    Optional<KevEntry> findByCveId(String cveId);

    boolean existsByCveId(String cveId);

    @Query("SELECT MAX(k.ingestedAt) FROM KevEntry k")
    Optional<Instant> findMaxIngestedAt();
}
