package io.castellum.discovery;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

@Repository
public interface DiscoverySweepRepository extends JpaRepository<DiscoverySweep, Long> {

    List<DiscoverySweep> findByStartedAtAfterOrderByStartedAtDesc(Instant since);
}
