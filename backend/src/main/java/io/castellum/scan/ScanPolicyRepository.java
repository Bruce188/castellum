package io.castellum.scan;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ScanPolicyRepository extends JpaRepository<ScanPolicy, Long> {

    List<ScanPolicy> findByEnabledTrue();

    Optional<ScanPolicy> findByName(String name);
}
