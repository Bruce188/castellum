package io.castellum.web.dto;

import io.castellum.domain.ScanStatus;
import java.time.Instant;
import java.util.List;

public record ScanDetailDto(
    Long id,
    String cidr,
    String scanType,
    ScanStatus status,
    Instant requestedAt,
    Instant completedAt,
    String failureReason,
    Integer retryCount,
    List<Long> discoveredDeviceIds
) {}
