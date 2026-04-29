package io.castellum.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface NetworkServiceRepository extends JpaRepository<NetworkService, Long> {

    List<NetworkService> findByDeviceId(Long deviceId);
}
