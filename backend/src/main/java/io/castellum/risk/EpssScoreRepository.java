package io.castellum.risk;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDate;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface EpssScoreRepository extends JpaRepository<EpssScore, Long> {
    Optional<EpssScore> findByCveId(String cveId);

    List<EpssScore> findAllByCveIdIn(Collection<String> cveIds);

    @Query("SELECT MAX(e.scoreDate) FROM EpssScore e")
    Optional<LocalDate> findMaxScoreDate();
}
