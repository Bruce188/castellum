package io.castellum.threatintel;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ThreatIntelPushRepository extends JpaRepository<ThreatIntelPushRecord, Long> {}
