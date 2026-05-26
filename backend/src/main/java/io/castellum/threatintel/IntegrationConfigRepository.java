package io.castellum.threatintel;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IntegrationConfigRepository extends JpaRepository<IntegrationConfig, Long> {

    Optional<IntegrationConfig> findByIntegrationType(String integrationType);
}
