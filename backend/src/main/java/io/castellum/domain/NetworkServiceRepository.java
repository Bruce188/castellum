package io.castellum.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface NetworkServiceRepository extends JpaRepository<NetworkService, Long> {

    List<NetworkService> findByDeviceId(Long deviceId);

    List<NetworkService> findByDeviceIdIn(Collection<Long> deviceIds);

    Optional<NetworkService> findByDeviceIdAndPortAndProtocol(Long deviceId, Integer port, String protocol);
}
