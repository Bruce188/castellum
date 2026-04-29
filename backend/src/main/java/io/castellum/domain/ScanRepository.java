package io.castellum.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ScanRepository extends JpaRepository<Scan, Long> {

    List<Scan> findByStatus(ScanStatus status);
}
