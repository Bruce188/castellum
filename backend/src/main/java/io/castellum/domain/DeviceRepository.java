package io.castellum.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface DeviceRepository extends JpaRepository<Device, Long> {

    Optional<Device> findByIpAddress(String ipAddress);

    List<Device> findByIpAddressIn(Collection<String> ipAddresses);

    List<Device> findByMacAddressIn(Collection<String> macAddresses);

    @Query("SELECT d.id FROM Device d WHERE d.firstSeen BETWEEN :from AND :to")
    List<Long> findIdsByFirstSeenBetween(
        @Param("from") Instant from,
        @Param("to") Instant to);
}
